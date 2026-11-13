use std::io::Cursor;

use serde::{Serialize, de::DeserializeOwned};

use crate::error::CoreError;

pub fn encode_cbor<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| CoreError::Encode(e.to_string()))?;
    Ok(out)
}

pub fn decode_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CoreError> {
    let mut cursor = Cursor::new(bytes);
    let value: T =
        ciborium::from_reader(&mut cursor).map_err(|e| CoreError::Decode(e.to_string()))?;
    let consumed = cursor.position();
    if consumed != bytes.len() as u64 {
        return Err(CoreError::Decode(format!(
            "{} trailing byte(s) after the CBOR value",
            bytes.len() as u64 - consumed
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_roundtrip() {
        let bytes = encode_cbor(&(7u64, "x")).unwrap();
        let back: (u64, String) = decode_cbor(&bytes).unwrap();
        assert_eq!(back, (7, "x".to_owned()));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode_cbor::<(u64, String)>(&trailing),
            Err(CoreError::Decode(_))
        ));
        assert!(matches!(
            decode_cbor::<(u64, String)>(&[0xff, 0xff]),
            Err(CoreError::Decode(_))
        ));
    }
}
