//! Canonical serialization helpers for PQ-PRIV.
//!
//! Transactions and blocks are encoded using CBOR with deterministic
//! ordering and little-endian numeric representations.  This crate wraps
//! `ciborium` so that serialization logic stays in a single place and the
//! rest of the codebase can rely on a consistent API.

use std::io::{self, Read, Write};

use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use serde::{Serialize, de::DeserializeOwned};

/// Serialize a value into CBOR using deterministic canonical form.
pub fn to_vec_cbor<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    write_cbor(value, &mut buf)?;
    Ok(buf)
}

/// Serialize a value into CBOR and write it into the provided sink.
pub fn write_cbor<T: Serialize, W: Write>(value: &T, mut writer: W) -> io::Result<()> {
    into_writer(value, &mut writer).map_err(map_ciborium_ser_err)
}

/// Deserialize a value from CBOR bytes.
pub fn from_slice_cbor<T: DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    read_cbor(bytes)
}

/// Deserialize a value from an arbitrary reader.
pub fn read_cbor<T: DeserializeOwned, R: Read>(reader: R) -> io::Result<T> {
    from_reader(reader).map_err(map_ciborium_err)
}

fn map_ciborium_err(error: ciborium::de::Error<std::io::Error>) -> io::Error {
    match error {
        ciborium::de::Error::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Dummy {
        value: u32,
        blob: Vec<u8>,
    }

    use serde::{Deserialize, Serialize};

    #[test]
    fn round_trips_struct() {
        let item = Dummy {
            value: 42,
            blob: vec![1, 2, 3],
        };
        let encoded = to_vec_cbor(&item).expect("encode");
        let decoded: Dummy = from_slice_cbor(&encoded).expect("decode");
        assert_eq!(decoded, item);
    }
}

fn map_ciborium_ser_err(error: ciborium::ser::Error<std::io::Error>) -> io::Error {
    match error {
        ciborium::ser::Error::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}
