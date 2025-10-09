use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::NetworkError;
use crate::types::NetMessage;

const MAX_VARINT_BYTES: usize = 5;

pub async fn read_message<R>(reader: &mut R, max_len: usize) -> Result<NetMessage, NetworkError>
where
    R: AsyncReadExt + Unpin,
{
    let len = read_varint(reader).await? as usize;
    if len > max_len {
        return Err(NetworkError::FrameTooLarge);
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let message: NetMessage = codec::from_slice_cbor(&buf).map_err(|err| match err.kind() {
        io::ErrorKind::InvalidData => NetworkError::Io(err),
        _ => NetworkError::Io(err),
    })?;
    Ok(message)
}

pub async fn write_message<W>(writer: &mut W, message: &NetMessage) -> Result<(), NetworkError>
where
    W: AsyncWriteExt + Unpin,
{
    let encoded = codec::to_vec_cbor(message)?;
    if encoded.len() > (u32::MAX as usize) {
        return Err(NetworkError::FrameTooLarge);
    }
    let mut header = Vec::with_capacity(MAX_VARINT_BYTES);
    write_varint(encoded.len() as u32, &mut header);
    writer.write_all(&header).await?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_varint<R>(reader: &mut R) -> Result<u32, NetworkError>
where
    R: AsyncReadExt + Unpin,
{
    let mut result: u32 = 0;
    let mut shift = 0;
    for _ in 0..MAX_VARINT_BYTES {
        let byte = reader.read_u8().await?;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(NetworkError::FrameTooLarge)
}

fn write_varint(value: u32, buf: &mut Vec<u8>) {
    let mut val = value;
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::BlockHeader;
    use tokio::io::duplex;

    #[tokio::test]
    async fn round_trips_message() {
        let (mut client, mut server) = duplex(64);
        let msg = NetMessage::Ping(42);
        write_message(&mut client, &msg).await.expect("write");
        let decoded = read_message(&mut server, 1024).await.expect("read");
        assert_eq!(decoded, msg);
    }

    #[tokio::test]
    async fn round_trips_headers_message() {
        let (mut client, mut server) = duplex(256);
        let header = BlockHeader {
            version: 1,
            prev_hash: [1u8; 32],
            merkle_root: [2u8; 32],
            utxo_root: [3u8; 32],
            time: 12345,
            n_bits: 0x207fffff,
            nonce: 99,
            alg_tag: 1,
        };
        let msg = NetMessage::Headers(vec![header.clone()]);
        write_message(&mut client, &msg)
            .await
            .expect("write headers");
        let decoded = read_message(&mut server, 1024).await.expect("read headers");
        assert_eq!(decoded, msg);
    }
}
