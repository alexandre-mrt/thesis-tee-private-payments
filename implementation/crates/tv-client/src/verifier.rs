use std::path::Path;

use tv_core::{Bytes32, SigningKey};

use crate::error::ClientError;
use crate::files::{PRIVATE_FILE_MODE, file_error, write_atomic};

pub const VERIFIER_KEY_KIND: &str = "verifier key";

pub fn write_verifier_key(path: &Path, key: &SigningKey) -> Result<(), ClientError> {
    if path.exists() {
        return Err(file_error(VERIFIER_KEY_KIND, path, &"already exists"));
    }
    write_atomic(
        path,
        hex::encode(key.to_bytes()).as_bytes(),
        PRIVATE_FILE_MODE,
    )
    .map_err(|e| file_error(VERIFIER_KEY_KIND, path, &e))
}

#[cfg(unix)]
fn check_private(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|e| file_error(VERIFIER_KEY_KIND, path, &e))?
        .permissions()
        .mode()
        & 0o777;
    if mode != PRIVATE_FILE_MODE {
        return Err(file_error(
            VERIFIER_KEY_KIND,
            path,
            &format!("has mode {mode:o}; a secret key file must be 600 (chmod 600)"),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

pub fn read_verifier_key(path: &Path) -> Result<SigningKey, ClientError> {
    check_private(path)?;
    let text =
        std::fs::read_to_string(path).map_err(|e| file_error(VERIFIER_KEY_KIND, path, &e))?;
    let bytes: Bytes32 = hex::decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| file_error(VERIFIER_KEY_KIND, path, &"is not 32 bytes of hex"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

#[cfg(test)]
mod tests;
