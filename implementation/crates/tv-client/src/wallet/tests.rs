use super::*;

fn temp_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("tv-wallet-{tag}-{nanos}.json"))
}

fn bank() -> BankKeys {
    BankKeys {
        state_pk: [1u8; 32],
        issuance_pk: [2u8; 32],
    }
}

#[test]
fn create_load_advance_and_locking() {
    let path = temp_path("basic");
    let seed = Seed::generate();
    let mut wallet = Wallet::create(&path, seed, bank()).unwrap();
    assert!(matches!(
        Wallet::load(&path),
        Err(ClientError::WalletLocked { .. })
    ));
    assert_eq!(wallet.balance(), 0);
    assert!(matches!(wallet.opening(), Err(ClientError::NotEnrolled)));
    let pk0 = wallet.current_pk().unwrap();
    wallet
        .set_enrolled(
            State {
                balance: 0,
                pk: pk0,
                r: wallet.r_at(0).unwrap(),
            },
            Signature([7u8; 64]),
        )
        .unwrap();
    wallet.advance(42, Signature([8u8; 64])).unwrap();
    assert_eq!(wallet.index(), 1);
    assert_eq!(wallet.balance(), 42);
    assert_eq!(
        wallet.state().unwrap().state.pk,
        wallet.current_pk().unwrap()
    );
    assert_ne!(pk0, wallet.current_pk().unwrap());
    let data = wallet.data().clone();
    drop(wallet);
    assert!(matches!(
        Wallet::create(&path, seed, bank()),
        Err(ClientError::File { what: "wallet", .. })
    ));
    let loaded = Wallet::load(&path).unwrap();
    assert_eq!(loaded.data(), &data);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    drop(loaded);
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(lock_path(&path)).unwrap();
}

#[test]
fn a_failed_save_names_the_wallet_file() {
    let path = temp_path("save");
    let mut wallet = Wallet::create(&path, Seed::generate(), bank()).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let err = wallet.set_pending(None).unwrap_err();
    assert!(
        matches!(err, ClientError::File { what: "wallet", .. }),
        "{err}"
    );
    assert!(
        err.to_string()
            .starts_with(&format!("wallet file {}: ", path.display())),
        "{err}"
    );
    drop(wallet);
    std::fs::remove_dir(&path).unwrap();
    std::fs::remove_file(lock_path(&path)).unwrap();
}

#[test]
fn loading_a_missing_wallet_names_it_and_leaves_no_lock_file() {
    let path = temp_path("missing");
    let nested = path.with_extension("dir").join("w.json");
    for missing in [&path, &nested] {
        let err = Wallet::load(missing).unwrap_err();
        assert!(
            err.to_string()
                .starts_with(&format!("wallet file {}: ", missing.display())),
            "{err}"
        );
        assert!(!lock_path(missing).exists());
    }
}
