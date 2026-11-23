use super::*;

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tv-verifier-{}-{name}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("verifier.key")
}

#[test]
fn a_verifier_key_round_trips_through_a_private_file_and_is_never_overwritten() {
    let path = scratch("roundtrip");
    let key = SigningKey::generate();
    write_verifier_key(&path, &key).unwrap();
    assert_eq!(read_verifier_key(&path).unwrap().to_bytes(), key.to_bytes());
    assert!(write_verifier_key(&path, &SigningKey::generate()).is_err());
    assert_eq!(read_verifier_key(&path).unwrap().to_bytes(), key.to_bytes());
}

#[cfg(unix)]
#[test]
fn a_verifier_key_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let path = scratch("mode");
    write_verifier_key(&path, &SigningKey::generate()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = read_verifier_key(&path).unwrap_err();
    assert!(err.to_string().contains("must be 600"), "{err}");
}

#[test]
fn a_verifier_key_file_that_is_not_a_key_is_refused() {
    let path = scratch("garbage");
    write_atomic(&path, b"zz", PRIVATE_FILE_MODE).unwrap();
    let err = read_verifier_key(&path).unwrap_err();
    assert!(err.to_string().contains("not 32 bytes of hex"), "{err}");
}
