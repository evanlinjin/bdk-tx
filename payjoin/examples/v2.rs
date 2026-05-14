//! Payjoin v2 example using `bdk_payjoin`'s sans-IO runtime.
//!
//! Two tokio tasks drive the receiver and sender independently. Each holds a
//! [`ReceiverSession`] / [`SenderSession`] and dispatches each [`ReceiverStep`]
//! / [`SenderStep`] variant against the example's `Wallet` / `Signer` directly
//! — no wallet trait is involved.

use anyhow::{anyhow, Result};
use bdk_payjoin::{
    input_pairs_from, sign_and_finalize_with_plans, FeeRange, OhttpKeys, ReceiverBuilder,
    ReceiverSession, ReceiverStep, SenderSession, SenderStep, Uri, UriExt,
};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable, group_by_spk, ChangeScript, Output, PsbtParams, SelectorParams, Signer,
};
use bitcoin::{
    consensus::encode::serialize_hex, key::Secp256k1, secp256k1::All, Amount, FeeRate, Psbt,
    Sequence, Transaction, Txid,
};
use miniscript::{Descriptor, DescriptorPublicKey};
use payjoin::io::fetch_ohttp_keys;
use std::{sync::Arc, time::Duration};
use tokio::sync::oneshot;
use url::Url;

mod common;
use common::Wallet;

const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[tokio::main]
async fn main() -> Result<()> {
    let ohttp_relay = Url::parse("https://pj.bobspacebkk.com")?;
    let payjoin_directory = Url::parse("https://payjo.in")?;
    let ohttp_keys = fetch_ohttp_keys(ohttp_relay.as_str(), payjoin_directory.as_str()).await?;

    let (receiver_wallet, receiver_signer, env, sender_wallet, sender_signer, sender_change_desc) =
        setup_wallets()?;
    let env = Arc::new(env);

    // Receiver tells the sender its BIP21 / Payjoin URI out of band (e.g. QR code).
    let (uri_tx, uri_rx) = oneshot::channel::<String>();

    let receiver_task = tokio::spawn(run_receiver(
        env.clone(),
        receiver_wallet,
        receiver_signer,
        ohttp_relay.clone(),
        payjoin_directory.clone(),
        ohttp_keys,
        uri_tx,
    ));
    let sender_task = tokio::spawn(run_sender(
        env.clone(),
        sender_wallet,
        sender_signer,
        sender_change_desc,
        ohttp_relay.clone(),
        uri_rx,
    ));

    let (receiver_res, sender_res) = tokio::join!(receiver_task, sender_task);
    let mut receiver_wallet = receiver_res??;
    let (mut sender_wallet, txid, network_fees) = sender_res??;
    println!("Sent: {txid}");

    env.mine_blocks(1, None)?;
    receiver_wallet.sync(&env)?;
    sender_wallet.sync(&env)?;

    let payjoin_tx = receiver_wallet
        .graph
        .graph()
        .get_tx(txid)
        .ok_or_else(|| anyhow!("payjoin tx not in receiver graph"))?;
    assert_eq!(payjoin_tx.input.len(), 2);
    assert_eq!(payjoin_tx.output.len(), 2);

    println!(
        "Sender confirmed: {} | Receiver confirmed: {} | Network fee: {}",
        sender_wallet.balance().confirmed,
        receiver_wallet.balance().confirmed,
        network_fees,
    );

    let sender_balance = sender_wallet.balance().confirmed;
    let receiver_balance = receiver_wallet.balance().confirmed;
    let forty_five = Amount::from_btc(45.0)?;
    let fifty_five = Amount::from_btc(55.0)?;
    assert!(sender_balance >= forty_five - network_fees && sender_balance <= forty_five);
    assert!(receiver_balance >= fifty_five - network_fees && receiver_balance <= fifty_five);

    Ok(())
}

// ---------------------------------------------------------------------------
// Receiver task
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_receiver(
    env: Arc<TestEnv>,
    mut wallet: Wallet,
    signer: Signer,
    ohttp_relay: Url,
    payjoin_directory: Url,
    ohttp_keys: OhttpKeys,
    uri_tx: oneshot::Sender<String>,
) -> Result<Wallet> {
    let secp = Secp256k1::new();

    let receiver_address = wallet.next_address().ok_or_else(|| anyhow!("no address"))?;
    let builder = ReceiverBuilder::new(receiver_address, payjoin_directory.as_str(), ohttp_keys)?;

    let fee_range = FeeRange {
        min: Some(FeeRate::BROADCAST_MIN),
        max: Some(FeeRate::from_sat_per_vb(2).expect("valid fee rate")),
    };
    let mut session = ReceiverSession::new(builder, ohttp_relay.as_str(), fee_range)?;

    uri_tx
        .send(session.pj_uri().to_string())
        .map_err(|_| anyhow!("sender dropped before receiving pj_uri"))?;

    let http = reqwest::Client::new();
    drive_receiver(&mut session, &http, &env, &mut wallet, &signer, &secp).await?;
    Ok(wallet)
}

async fn drive_receiver(
    session: &mut ReceiverSession,
    http: &reqwest::Client,
    env: &TestEnv,
    wallet: &mut Wallet,
    signer: &Signer,
    secp: &Secp256k1<All>,
) -> Result<()> {
    loop {
        match session.poll() {
            ReceiverStep::Save(events) => {
                // Production callers persist atomically. The example logs.
                println!("[recv] would persist {} event(s)", events.len());
            }
            ReceiverStep::SendRequest(req) => {
                let bytes = send(http, req).await?;
                session.feed_response(bytes)?;
            }
            ReceiverStep::Backoff => tokio::time::sleep(POLL_INTERVAL).await,
            ReceiverStep::CheckBroadcast(tx) => {
                let ok = test_mempool_accept(env, &tx)?;
                session.feed_broadcast_check(ok)?;
            }
            ReceiverStep::ResolveOwned(spks) => {
                let answers = spks
                    .iter()
                    .map(|spk| wallet.graph.index.index_of_spk(spk.clone()).is_some())
                    .collect::<Vec<_>>();
                session.feed_owned(answers)?;
            }
            ReceiverStep::Contribute => {
                let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;
                let candidates = wallet
                    .all_candidates()
                    .filter(|input| input.is_spendable(tip_height, Some(tip_time)));
                let inputs = input_pairs_from(&candidates, Sequence::ENABLE_RBF_NO_LOCKTIME);
                session.feed_contribute(inputs)?;
            }
            ReceiverStep::SignAndFinalize(mut psbt) => {
                let assets = wallet.assets();
                sign_and_finalize_with_plans(
                    &mut psbt,
                    |op| wallet.plan_of_output(op, &assets),
                    |psbt| {
                        psbt.sign(signer, secp).map_err(|(_, errs)| {
                            bdk_payjoin::Error::Wallet(format!("sign: {errs:?}"))
                        })?;
                        Ok(())
                    },
                )?;
                session.feed_signed_psbt(psbt)?;
            }
            ReceiverStep::Done => return Ok(()),
            ReceiverStep::Failed(e) => return Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Sender task
// ---------------------------------------------------------------------------

async fn run_sender(
    env: Arc<TestEnv>,
    mut wallet: Wallet,
    signer: Signer,
    change_desc: Descriptor<DescriptorPublicKey>,
    ohttp_relay: Url,
    uri_rx: oneshot::Receiver<String>,
) -> Result<(Wallet, Txid, Amount)> {
    let secp = Secp256k1::new();

    let uri_str = uri_rx.await.map_err(|_| anyhow!("receiver dropped pj_uri"))?;
    let pj_uri = Uri::try_from(uri_str.as_str())
        .map_err(|e| anyhow!("{e}"))?
        .assume_checked()
        .check_pj_supported()
        .map_err(|e| anyhow!("{e}"))?;

    let psbt = build_original_psbt(&env, &wallet, &signer, &pj_uri, &change_desc, &secp)?;
    let mut session =
        SenderSession::new(psbt, pj_uri, ohttp_relay.as_str(), FeeRate::BROADCAST_MIN)?;

    let http = reqwest::Client::new();
    drive_sender(&mut session, &http, &mut wallet, &signer, &secp).await?;

    let tx = session
        .final_tx()
        .ok_or_else(|| anyhow!("session ended without tx"))?
        .clone();
    let fee = session.fee().expect("done implies fee");
    let txid = env.rpc_client().send_raw_transaction(&tx)?;
    Ok((wallet, txid, fee))
}

async fn drive_sender(
    session: &mut SenderSession,
    http: &reqwest::Client,
    wallet: &mut Wallet,
    signer: &Signer,
    secp: &Secp256k1<All>,
) -> Result<()> {
    loop {
        match session.poll() {
            SenderStep::Save(events) => {
                println!("[send] would persist {} event(s)", events.len());
            }
            SenderStep::SendRequest(req) => {
                let bytes = send(http, req).await?;
                session.feed_response(bytes)?;
            }
            SenderStep::Backoff => tokio::time::sleep(POLL_INTERVAL).await,
            SenderStep::SignAndFinalize(mut psbt) => {
                let assets = wallet.assets();
                // Payjoin already restored UTXOs on the sender's inputs inside
                // process_proposal — the PSBT here is signer-ready. Just sign
                // and finalize.
                sign_and_finalize_with_plans(
                    &mut psbt,
                    |op| wallet.plan_of_output(op, &assets),
                    |psbt| {
                        psbt.sign(signer, secp).map_err(|(_, errs)| {
                            bdk_payjoin::Error::Wallet(format!("sign: {errs:?}"))
                        })?;
                        Ok(())
                    },
                )?;
                session.feed_signed_psbt(psbt)?;
            }
            SenderStep::Done => return Ok(()),
            SenderStep::Failed(e) => return Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Side helpers
// ---------------------------------------------------------------------------

fn test_mempool_accept(env: &TestEnv, tx: &Transaction) -> Result<bool> {
    let res = env.rpc_client().test_mempool_accept(&[serialize_hex(tx)])?;
    Ok(res
        .first()
        .ok_or_else(|| anyhow!("empty testmempoolaccept response"))?
        .allowed)
}

async fn send(http: &reqwest::Client, req: bdk_payjoin::Request) -> Result<Vec<u8>> {
    let resp = http
        .post(req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow!("directory error: {}", resp.status()));
    }
    Ok(resp.bytes().await?.to_vec())
}

// ---------------------------------------------------------------------------
// Original-PSBT construction (pure bdk_tx).
// ---------------------------------------------------------------------------

fn build_original_psbt(
    env: &TestEnv,
    wallet: &Wallet,
    signer: &Signer,
    pj_uri: &bdk_payjoin::PjUri,
    change_desc: &Descriptor<DescriptorPublicKey>,
    secp: &Secp256k1<All>,
) -> Result<Psbt> {
    let (tip_height, tip_time) = wallet.tip_info(env.rpc_client())?;
    let target_amount = Amount::from_btc(5.0)?;
    let target_feerate = FeeRate::from_sat_per_vb(2).expect("valid fee rate");
    let longterm_feerate = FeeRate::from_sat_per_vb(1).expect("valid fee rate");

    let target_outputs = vec![Output::with_script(
        pj_uri.address.script_pubkey(),
        target_amount,
    )];

    let selection = wallet
        .all_candidates()
        .regroup(group_by_spk())
        .filter(filter_unspendable(tip_height, Some(tip_time)))
        .into_selection(
            |selector| -> Result<()> {
                selector.select_all();
                Ok(())
            },
            SelectorParams {
                change_longterm_feerate: Some(longterm_feerate),
                ..SelectorParams::new(
                    target_feerate,
                    target_outputs,
                    ChangeScript::from_descriptor(change_desc.at_derivation_index(0)?),
                )
            },
        )?;

    let mut psbt = selection.create_psbt(PsbtParams {
        fallback_sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        ..Default::default()
    })?;
    let finalizer = selection.into_finalizer();
    let _ = psbt.sign(signer, secp);
    if !finalizer.finalize(&mut psbt).is_finalized() {
        return Err(anyhow!("failed to finalize original PSBT"));
    }
    Ok(psbt)
}

// ---------------------------------------------------------------------------
// Wallet setup (test fixture).
// ---------------------------------------------------------------------------

pub fn setup_wallets() -> Result<(
    Wallet,
    Signer,
    TestEnv,
    Wallet,
    Signer,
    Descriptor<DescriptorPublicKey>,
)> {
    let secp = Secp256k1::new();

    let (receiver_external, receiver_external_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[0])?;
    let (receiver_internal, receiver_internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[1])?;

    let receiver_signer: Signer = Signer(
        receiver_external_keymap
            .into_iter()
            .chain(receiver_internal_keymap)
            .collect(),
    );

    let (sender_external, sender_external_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[3])?;
    let (sender_internal, sender_internal_keymap) =
        Descriptor::parse_descriptor(&secp, bdk_testenv::utils::DESCRIPTORS[4])?;

    let sender_signer: Signer = Signer(
        sender_external_keymap
            .into_iter()
            .chain(sender_internal_keymap)
            .collect(),
    );

    let env = TestEnv::new()?;
    let genesis_hash = env.genesis_hash()?;
    env.mine_blocks(101, None)?;

    let mut receiver_wallet =
        Wallet::new(genesis_hash, receiver_external, receiver_internal.clone())?;
    receiver_wallet.sync(&env)?;
    let receiver_addr = receiver_wallet.next_address().expect("must derive address");
    let receiver_txid = env.send(&receiver_addr, Amount::from_btc(50.0)?)?;
    env.mine_blocks(1, None)?;
    receiver_wallet.sync(&env)?;
    println!("Receiver Received {receiver_txid}");
    println!(
        "Receiver Balance (confirmed): {}",
        receiver_wallet.balance()
    );

    let mut sender_wallet = Wallet::new(genesis_hash, sender_external, sender_internal.clone())?;
    sender_wallet.sync(&env)?;
    let sender_addr = sender_wallet.next_address().expect("must derive address");
    let sender_txid = env.send(&sender_addr, Amount::from_btc(50.0)?)?;
    env.mine_blocks(1, None)?;
    sender_wallet.sync(&env)?;
    println!("Sender Received {sender_txid}");
    println!("Sender Balance (confirmed): {}", sender_wallet.balance());

    Ok((
        receiver_wallet,
        receiver_signer,
        env,
        sender_wallet,
        sender_signer,
        sender_internal,
    ))
}
