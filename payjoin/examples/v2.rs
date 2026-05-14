//! Payjoin v2 example using `bdk_payjoin`'s high-level runtime.
//!
//! Two tokio tasks drive the receiver and sender independently. Each holds a
//! [`ReceiverSession`] / [`SenderSession`] and a tiny adapter struct that
//! implements [`ReceiverWallet`] / [`SenderWallet`] over the example's `Wallet`
//! type. A single `drive_session` helper turns the sans-IO step API into
//! reqwest HTTP calls.

use anyhow::{anyhow, Result};
use bdk_payjoin::{
    input_pairs_from, restore_psbt_utxos, sign_and_finalize_with_plans, FeeRange,
    ImplementationError, InputPair, OhttpKeys, ReceiverBuilder, ReceiverSession, ReceiverWallet,
    SenderSession, SenderWallet, Step, Uri, UriExt,
};
use bdk_testenv::{bitcoincore_rpc::RpcApi, TestEnv};
use bdk_tx::{
    filter_unspendable, group_by_spk, ChangeScript, Output, PsbtParams, SelectorParams, Signer,
};
use bitcoin::{
    consensus::encode::serialize_hex, key::Secp256k1, secp256k1::All, Amount, FeeRate, Psbt, Script,
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
    let receiver_address = wallet.next_address().ok_or_else(|| anyhow!("no address"))?;
    let builder = ReceiverBuilder::new(receiver_address, payjoin_directory.as_str(), ohttp_keys)?;

    let adapter = RecvAdapter {
        wallet,
        env,
        signer,
        secp: Secp256k1::new(),
    };
    let fee_range = FeeRange {
        min: Some(FeeRate::BROADCAST_MIN),
        max: Some(FeeRate::from_sat_per_vb(2).expect("valid fee rate")),
    };
    let mut session = ReceiverSession::new(builder, ohttp_relay.as_str(), adapter, fee_range)?;

    uri_tx
        .send(session.pj_uri().to_string())
        .map_err(|_| anyhow!("sender dropped before receiving pj_uri"))?;

    let http = reqwest::Client::new();
    drive_receiver(&mut session, &http).await?;

    Ok(session.into_wallet().wallet)
}

struct RecvAdapter {
    wallet: Wallet,
    env: Arc<TestEnv>,
    signer: Signer,
    secp: Secp256k1<All>,
}

impl ReceiverWallet for RecvAdapter {
    fn is_owned(&self, spk: &Script) -> bool {
        self.wallet
            .graph
            .index
            .index_of_spk(spk.to_owned())
            .is_some()
    }

    fn check_broadcast(&self, tx: &Transaction) -> Result<bool, ImplementationError> {
        let res = self
            .env
            .rpc_client()
            .test_mempool_accept(&[serialize_hex(tx)])
            .map_err(ImplementationError::new)?;
        Ok(res
            .first()
            .ok_or_else(|| ImplementationError::from("empty testmempoolaccept response"))?
            .allowed)
    }

    fn contribute(&self) -> Result<Vec<InputPair>, bdk_payjoin::Error> {
        let (tip_height, tip_time) = self
            .wallet
            .tip_info(self.env.rpc_client())
            .map_err(|e| bdk_payjoin::Error::Wallet(e.to_string()))?;
        let candidates = self
            .wallet
            .all_candidates()
            .filter(|input| input.is_spendable(tip_height, Some(tip_time)));
        Ok(input_pairs_from(&candidates, Sequence::ENABLE_RBF_NO_LOCKTIME))
    }

    fn process_psbt(&self, psbt: &mut Psbt) -> Result<(), bdk_payjoin::Error> {
        let assets = self.wallet.assets();
        sign_and_finalize_with_plans(
            psbt,
            |op| self.wallet.plan_of_output(op, &assets),
            |psbt| {
                psbt.sign(&self.signer, &self.secp).map_err(|(_, errs)| {
                    bdk_payjoin::Error::Wallet(format!("sign: {errs:?}"))
                })?;
                Ok(())
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Sender task
// ---------------------------------------------------------------------------

async fn run_sender(
    env: Arc<TestEnv>,
    wallet: Wallet,
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

    let adapter = SendAdapter {
        wallet,
        signer,
        secp,
    };
    let mut session = SenderSession::new(
        psbt,
        pj_uri,
        ohttp_relay.as_str(),
        adapter,
        FeeRate::BROADCAST_MIN,
    )?;

    let http = reqwest::Client::new();
    drive_sender(&mut session, &http).await?;

    let tx = session
        .final_tx()
        .ok_or_else(|| anyhow!("session ended without tx"))?
        .clone();
    let fee = session.fee().expect("done implies fee");
    let txid = env.rpc_client().send_raw_transaction(&tx)?;
    Ok((session.into_wallet().wallet, txid, fee))
}

struct SendAdapter {
    wallet: Wallet,
    signer: Signer,
    secp: Secp256k1<All>,
}

impl SenderWallet for SendAdapter {
    fn process_psbt(&self, psbt: &mut Psbt) -> Result<(), bdk_payjoin::Error> {
        let assets = self.wallet.assets();
        // 1. Restore witness/non-witness UTXOs the proposal sanitized away.
        restore_psbt_utxos(
            psbt,
            |op| self.wallet.plan_of_output(op, &assets).is_some(),
            |txid| {
                self.wallet
                    .graph
                    .graph()
                    .get_tx(txid)
                    .map(|t| t.as_ref().clone())
            },
        );
        // 2 + 3. Sign and finalize the sender's inputs.
        sign_and_finalize_with_plans(
            psbt,
            |op| self.wallet.plan_of_output(op, &assets),
            |psbt| {
                psbt.sign(&self.signer, &self.secp).map_err(|(_, errs)| {
                    bdk_payjoin::Error::Wallet(format!("sign: {errs:?}"))
                })?;
                Ok(())
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Drive loops — turn sans-IO Steps into reqwest calls.
// ---------------------------------------------------------------------------

async fn drive_receiver<W: ReceiverWallet>(
    session: &mut ReceiverSession<W>,
    http: &reqwest::Client,
) -> Result<()> {
    loop {
        match session.poll() {
            Step::SendRequest(req) => {
                let bytes = send(http, req).await?;
                session.feed_response(bytes)?;
            }
            Step::Backoff => tokio::time::sleep(POLL_INTERVAL).await,
            Step::Done => return Ok(()),
            Step::Failed(e) => return Err(e.into()),
        }
    }
}

async fn drive_sender<W: SenderWallet>(
    session: &mut SenderSession<W>,
    http: &reqwest::Client,
) -> Result<()> {
    loop {
        match session.poll() {
            Step::SendRequest(req) => {
                let bytes = send(http, req).await?;
                session.feed_response(bytes)?;
            }
            Step::Backoff => tokio::time::sleep(POLL_INTERVAL).await,
            Step::Done => return Ok(()),
            Step::Failed(e) => return Err(e.into()),
        }
    }
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
// Original-PSBT construction (unchanged from before — pure bdk_tx).
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
