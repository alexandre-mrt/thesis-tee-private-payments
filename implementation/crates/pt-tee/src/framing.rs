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
