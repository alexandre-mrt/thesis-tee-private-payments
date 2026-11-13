//! Length-prefixed CBOR framing (SPEC section 7).
//!
//! A frame is a 4-byte big-endian body length followed by the body. Bodies
//! larger than [`MAX_FRAME_LEN`] are rejected before any body byte is read or
//! allocated. The CBOR helpers encode with `ciborium` and reject trailing
//! bytes after the top-level value.

use std::io::{Cursor, ErrorKind};

use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::MAX_FRAME_LEN;

/// Size of the length prefix in bytes.
pub const LEN_PREFIX: usize = 4;

/// Errors of the framing layer.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The peer closed the connection exactly at a frame boundary.
    #[error("peer closed the connection at a frame boundary")]
    Closed,
    /// A frame announced (or a caller requested) a body above the cap.
    #[error("frame length {len} exceeds the cap of {max} bytes")]
    TooLarge { len: u64, max: usize },
    /// Underlying I/O failure, including truncated frames.
    #[error("i/o error on frame: {0}")]
    Io(#[from] std::io::Error),
    /// CBOR serialization failed.
    #[error("CBOR encoding failed: {0}")]
    Encode(String),
    /// CBOR deserialization failed or left trailing bytes.
    #[error("CBOR decoding failed: {0}")]
    Decode(String),
}

/// Writes one frame (length prefix + body) and flushes.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), FrameError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge {
            len: body.len() as u64,
            max: MAX_FRAME_LEN,
        });
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge {
        len: body.len() as u64,
        max: MAX_FRAME_LEN,
    })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one frame body of at most [`MAX_FRAME_LEN`] bytes.
///
/// Returns [`FrameError::Closed`] if the stream ends before the first byte of
/// the length prefix, [`FrameError::TooLarge`] if the announced length exceeds
/// [`MAX_FRAME_LEN`] (checked before allocating), and an
/// [`ErrorKind::UnexpectedEof`] I/O error if the frame is truncated.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    read_frame_bounded(reader, MAX_FRAME_LEN).await
}

/// Reads one frame body, refusing announced lengths above `max` (itself capped
/// at [`MAX_FRAME_LEN`]) without ever allocating for them.
///
/// A refused body that still fits the protocol cap is read and discarded
/// through a fixed-size buffer so an error response can reach the peer:
/// closing a socket with unread bytes makes the kernel send a reset instead.
/// Bodies above the protocol cap are not a valid frame at all and are not
/// drained. Peers that only expect small messages (the client expects an
/// attestation document and a sealed proof) pass a small `max` so a malicious
/// peer cannot make them allocate 32 MiB from a header alone.
pub async fn read_frame_bounded<R: AsyncRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> Result<Vec<u8>, FrameError> {
    let max = max.min(MAX_FRAME_LEN);
    let mut header = [0u8; LEN_PREFIX];
    let first = reader.read(&mut header).await?;
    if first == 0 {
        return Err(FrameError::Closed);
    }
    reader.read_exact(&mut header[first..]).await?;
    let len = u32::from_be_bytes(header) as usize;
    if len > max {
        if len <= MAX_FRAME_LEN {
            tokio::io::copy(&mut reader.take(len as u64), &mut tokio::io::sink()).await?;
        }
        return Err(FrameError::TooLarge {
            len: len as u64,
            max,
        });
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

/// Encodes a value as CBOR.
pub fn encode_cbor<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| FrameError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decodes exactly one CBOR value; trailing bytes are an error.
pub fn decode_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, FrameError> {
    let mut cursor = Cursor::new(bytes);
    let value: T =
        ciborium::from_reader(&mut cursor).map_err(|e| FrameError::Decode(e.to_string()))?;
    let consumed = cursor.position();
    if consumed != bytes.len() as u64 {
        return Err(FrameError::Decode(format!(
            "{} trailing byte(s) after the CBOR value",
            bytes.len() as u64 - consumed
        )));
    }
    Ok(value)
}

/// Encodes `value` as CBOR and writes it as one frame.
pub async fn write_cbor<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let body = encode_cbor(value)?;
    write_frame(writer, &body).await
}

/// Reads one frame and decodes its body as CBOR.
pub async fn read_cbor<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let body = read_frame(reader).await?;
    decode_cbor(&body)
}

/// Reads one frame of at most `max` body bytes and decodes it as CBOR.
pub async fn read_cbor_bounded<R, T>(reader: &mut R, max: usize) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let body = read_frame_bounded(reader, max).await?;
    decode_cbor(&body)
}

/// True if the error is a truncated frame (EOF in the middle of a frame).
pub fn is_truncated(err: &FrameError) -> bool {
    matches!(err, FrameError::Io(e) if e.kind() == ErrorKind::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use tokio::io::duplex;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    enum Msg {
        Attest {
            nonce: [u8; 32],
        },
        Sealed {
            nonce: [u8; 12],
            #[serde(with = "serde_bytes")]
            ciphertext: Vec<u8>,
        },
    }

    #[tokio::test]
    async fn roundtrip_bytes_and_empty_frame() {
        let (mut a, mut b) = duplex(16);
        let payload = vec![7u8; 1000];
        let sent = payload.clone();
        let writer = tokio::spawn(async move {
            write_frame(&mut a, &sent).await.unwrap();
            write_frame(&mut a, &[]).await.unwrap();
            a
        });
        assert_eq!(read_frame(&mut b).await.unwrap(), payload);
        assert_eq!(read_frame(&mut b).await.unwrap(), Vec::<u8>::new());
        drop(writer.await.unwrap());
        assert!(matches!(read_frame(&mut b).await, Err(FrameError::Closed)));
    }

    #[tokio::test]
    async fn oversize_length_is_rejected_before_reading_body() {
        let (mut a, mut b) = duplex(16);
        let len = (MAX_FRAME_LEN as u32 + 1).to_be_bytes();
        a.write_all(&len).await.unwrap();
        // No body is ever written: the reader must fail on the header alone.
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(
            matches!(err, FrameError::TooLarge { len, max } if len == MAX_FRAME_LEN as u64 + 1 && max == MAX_FRAME_LEN)
        );
    }

    #[tokio::test]
    async fn exact_cap_header_is_accepted() {
        let (mut a, mut b) = duplex(16);
        let len = (MAX_FRAME_LEN as u32).to_be_bytes();
        a.write_all(&len).await.unwrap();
        drop(a);
        // Header accepted, then truncation: an UnexpectedEof, not TooLarge.
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(is_truncated(&err), "{err:?}");
    }

    #[tokio::test]
    async fn truncated_body_and_truncated_header_are_io_errors() {
        let (mut a, mut b) = duplex(16);
        a.write_all(&10u32.to_be_bytes()).await.unwrap();
        a.write_all(&[1, 2, 3]).await.unwrap();
        drop(a);
        assert!(is_truncated(&read_frame(&mut b).await.unwrap_err()));

        let (mut a, mut b) = duplex(16);
        a.write_all(&[0, 0]).await.unwrap();
        drop(a);
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(is_truncated(&err));
        assert!(!matches!(err, FrameError::Closed));
    }

    #[tokio::test]
    async fn bounded_read_refuses_oversize_and_drains_its_body() {
        let (mut a, mut b) = duplex(16);
        tokio::spawn(async move {
            a.write_all(&(1001u32).to_be_bytes()).await.unwrap();
            a.write_all(&[7u8; 1001]).await.unwrap();
            // A well-formed frame right after the refused one.
            a.write_all(&(1u32).to_be_bytes()).await.unwrap();
            a.write_all(&[9u8]).await.unwrap();
        });
        let err = read_frame_bounded(&mut b, 1000).await.unwrap_err();
        assert!(
            matches!(
                err,
                FrameError::TooLarge {
                    len: 1001,
                    max: 1000
                }
            ),
            "{err:?}"
        );
        // The refused body was consumed: the stream is positioned on the next frame.
        assert_eq!(read_frame_bounded(&mut b, 1000).await.unwrap(), vec![9u8]);

        // Above the protocol cap: refused immediately, nothing drained, and a
        // caller's cap above the protocol cap is clamped to it.
        let (mut a, mut b) = duplex(16);
        a.write_all(&(MAX_FRAME_LEN as u32 + 1).to_be_bytes())
            .await
            .unwrap();
        let err = read_frame_bounded(&mut b, usize::MAX).await.unwrap_err();
        assert!(
            matches!(err, FrameError::TooLarge { max, .. } if max == MAX_FRAME_LEN),
            "{err:?}"
        );

        let (a, mut b) = duplex(16);
        drop(a);
        assert!(matches!(
            read_frame_bounded(&mut b, 1000).await,
            Err(FrameError::Closed)
        ));
    }

    #[tokio::test]
    async fn write_frame_refuses_oversize_body() {
        let (mut a, _b) = duplex(16);
        let body = vec![0u8; MAX_FRAME_LEN + 1];
        let err = write_frame(&mut a, &body).await.unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { .. }));
    }

    #[tokio::test]
    async fn cbor_roundtrip_over_a_stream() {
        let (mut a, mut b) = duplex(64);
        let m1 = Msg::Attest { nonce: [9u8; 32] };
        let m2 = Msg::Sealed {
            nonce: [1u8; 12],
            ciphertext: vec![0xAB; 300],
        };
        let (s1, s2) = (m1.clone(), m2.clone());
        let writer = tokio::spawn(async move {
            write_cbor(&mut a, &s1).await.unwrap();
            write_cbor(&mut a, &s2).await.unwrap();
        });
        let r1: Msg = read_cbor(&mut b).await.unwrap();
        let r2: Msg = read_cbor(&mut b).await.unwrap();
        writer.await.unwrap();
        assert_eq!(r1, m1);
        assert_eq!(r2, m2);
    }

    #[test]
    fn cbor_rejects_trailing_bytes_and_garbage() {
        let mut bytes = encode_cbor(&Msg::Attest { nonce: [0u8; 32] }).unwrap();
        assert!(decode_cbor::<Msg>(&bytes).is_ok());
        bytes.push(0x00);
        let err = decode_cbor::<Msg>(&bytes).unwrap_err();
        assert!(
            matches!(err, FrameError::Decode(ref m) if m.contains("trailing")),
            "{err}"
        );
        assert!(matches!(
            decode_cbor::<Msg>(&[0xFF, 0xFF]),
            Err(FrameError::Decode(_))
        ));
        assert!(matches!(
            decode_cbor::<Msg>(&[]),
            Err(FrameError::Decode(_))
        ));
    }

    #[test]
    fn bytes_fields_encode_as_cbor_byte_strings() {
        // serde_bytes must give a CBOR byte string (major type 2), not an array.
        let bytes = encode_cbor(&Msg::Sealed {
            nonce: [0u8; 12],
            ciphertext: vec![1, 2, 3],
        })
        .unwrap();
        let needle = [0x43u8, 1, 2, 3];
        assert!(bytes.windows(4).any(|w| w == needle), "{bytes:02x?}");
    }
}
