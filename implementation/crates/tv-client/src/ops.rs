use std::path::{Path, PathBuf};

use pt_tee::transport::Endpoint;
use tv_core::{BankKeys, Seed, SignedState};

use crate::attest::Trust;
use crate::bank::BankClient;
use crate::error::ClientError;
use crate::files::{OfferFile, ReceiptFile, RequestFile, read_json, write_json};
use crate::recover::Debits;
use crate::wallet::{Pending, Wallet};
use crate::{flows, payment, recover};

pub struct Session {
    wallet_path: PathBuf,
    bank: BankClient,
}

pub fn create_wallet(
    path: &Path,
    seed: Option<Seed>,
    bank: BankKeys,
) -> Result<String, ClientError> {
    let wallet = Wallet::create(path, seed.unwrap_or_else(Seed::generate), bank)?;
    Ok(format!(
        "wallet {} created, pk_0={}",
        path.display(),
        hex::encode(wallet.current_pk()?)
    ))
}

pub fn seed_hex(path: &Path) -> Result<String, ClientError> {
    Ok(Wallet::load(path)?.seed().to_hex())
}

pub fn balance(path: &Path) -> Result<String, ClientError> {
    balance_line(&Wallet::load(path)?)
}

pub fn balance_line(wallet: &Wallet) -> Result<String, ClientError> {
    let pending = wallet.pending().map_or("none", Pending::what);
    let membership = if wallet.is_bank_state() {
        String::new()
    } else {
        format!(" enrolled={}", wallet.state().is_some())
    };
    Ok(format!(
        "balance={} index={}{membership} pending={pending} pk={}",
        wallet.balance(),
        wallet.index(),
        hex::encode(wallet.current_pk()?)
    ))
}

fn balance_line_after(wallet: &Wallet, refreshed: flows::Refreshed) -> Result<String, ClientError> {
    let what = match refreshed {
        flows::Refreshed::Moved => "refreshed",
        flows::Refreshed::FinishedSettledPayment => {
            "the pending payment had already settled, finished it instead of abandoning it"
        }
    };
    Ok(format!("{what}: {}", balance_line(wallet)?))
}

fn recovered_line(steps: u64, wallet: &Wallet) -> Result<String, ClientError> {
    Ok(format!(
        "recovered {steps} state transition(s): {}",
        balance_line(wallet)?
    ))
}

impl Session {
    pub fn open(wallet_path: &Path, bank_addr: &str, trust: &Trust) -> Result<Self, ClientError> {
        let bank = BankClient::new(Endpoint::tcp(bank_addr)?, trust)?;
        Ok(Self {
            wallet_path: wallet_path.to_path_buf(),
            bank,
        })
    }

    pub fn bank(&self) -> &BankClient {
        &self.bank
    }

    fn wallet(&self) -> Result<Wallet, ClientError> {
        Wallet::load(&self.wallet_path)
    }

    pub async fn enroll(&self) -> Result<String, ClientError> {
        let mut wallet = self.wallet()?;
        flows::enroll_and_refresh(&mut wallet, &self.bank).await?;
        Ok(format!(
            "enrolled and moved off pk_0: {}",
            balance_line(&wallet)?
        ))
    }

    pub async fn request(&self, amount: Option<u64>, out: &Path) -> Result<String, ClientError> {
        let mut wallet = self.wallet()?;
        let request = payment::request(&mut wallet, &self.bank, amount).await?;
        write_json(out, "request", &request)?;
        Ok(format!(
            "request for {} written to {} (payee serial {})",
            request.v,
            out.display(),
            hex::encode(request.pk_b)
        ))
    }

    pub fn pay_offer_with<E: From<ClientError>>(
        &self,
        request: &Path,
        out: &Path,
        reseal: bool,
        before_commit: impl FnOnce(&RequestFile, &OfferFile) -> Result<(), E>,
    ) -> Result<(RequestFile, OfferFile), E> {
        let mut wallet = self.wallet()?;
        if reseal && !matches!(wallet.pending(), Some(Pending::Pay { .. })) {
            return Err(ClientError::NoPending { what: "payment" }.into());
        }
        let request: RequestFile = read_json(request, "request")?;
        let prepared = payment::prepare_pay(&wallet, self.bank.verifier(), &request)?;
        before_commit(&request, &prepared.offer)?;
        let offer = payment::commit_pay(&mut wallet, prepared)?;
        write_json(out, "offer", &offer)?;
        Ok((request, offer))
    }

    pub fn pay(&self, request: &Path, out: &Path, agreed: u64) -> Result<String, ClientError> {
        let (request, _) = self.pay_offer_with(request, out, false, |request, _| {
            if request.v == agreed {
                Ok(())
            } else {
                Err(ClientError::PayAmount {
                    agreed,
                    requested: request.v,
                })
            }
        })?;
        Ok(format!(
            "offer of {} to {} written to {}",
            request.v,
            hex::encode(request.pk_b),
            out.display()
        ))
    }

    pub fn reseal(&self, request: &Path, out: &Path) -> Result<String, ClientError> {
        let (request, _) =
            self.pay_offer_with(request, out, true, |_, _| Ok::<(), ClientError>(()))?;
        Ok(format!(
            "offer of {} to {} resealed to {}",
            request.v,
            hex::encode(request.pk_b),
            out.display()
        ))
    }

    pub async fn receive(&self, offer: &Path, out: &Path) -> Result<String, ClientError> {
        let mut wallet = self.wallet()?;
        let offer: OfferFile = read_json(offer, "offer")?;
        let prepared = payment::prepare_receive(&wallet, &offer)?;
        let settled = payment::submit_receive(&wallet, &self.bank, &prepared).await?;
        write_json(out, "receipt", &settled.receipt)?;
        payment::commit_receive(&mut wallet, &settled)?;
        Ok(format!(
            "settled, receipt written to {}: {}",
            out.display(),
            balance_line(&wallet)?
        ))
    }

    pub async fn finish(&self, receipt: Option<&Path>) -> Result<String, ClientError> {
        let mut wallet = self.wallet()?;
        let receipt: Option<ReceiptFile> = receipt.map(|p| read_json(p, "receipt")).transpose()?;
        flows::finish(&mut wallet, &self.bank, receipt.as_ref()).await?;
        Ok(format!("finished: {}", balance_line(&wallet)?))
    }

    pub async fn refresh(&self, force: bool) -> Result<String, ClientError> {
        let mut wallet = self.wallet()?;
        let refreshed = flows::refresh(&mut wallet, &self.bank, force).await?;
        balance_line_after(&wallet, refreshed)
    }

    pub async fn recover(&self) -> Result<String, ClientError> {
        let mut wallet = self.wallet()?;
        let steps = recover::recover(&mut wallet, &self.bank).await?;
        recovered_line(steps, &wallet)
    }

    pub async fn recover_from_genesis(
        &self,
        genesis: SignedState,
        debits: &Debits,
    ) -> Result<String, ClientError> {
        let mut wallet = self.wallet()?;
        let steps = recover::recover_from_genesis(&mut wallet, &self.bank, genesis, debits).await?;
        recovered_line(steps, &wallet)
    }
}
