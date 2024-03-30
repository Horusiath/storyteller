use std::array::TryFromSliceError;
use std::fmt::{Debug, Display, Formatter};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};

use blake3::Hash;
use bytes::Bytes;
use ed25519::{ComponentBytes, Signature};
use ed25519_dalek::{SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef};
use rusqlite::{Row, ToSql};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use varint_rs::{VarintReader, VarintWriter};

use crate::{PeerID, Result};

#[repr(transparent)]
#[derive(Copy, Clone, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ID([u8; blake3::OUT_LEN]);

impl Deref for ID {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl DerefMut for ID {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut_slice()
    }
}

impl From<Hash> for ID {
    fn from(value: Hash) -> Self {
        ID(value.into())
    }
}

impl TryFrom<&[u8]> for ID {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let value: [u8; blake3::OUT_LEN] = value.try_into()?;
        Ok(ID(value))
    }
}

impl FromSql for ID {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        if let ValueRef::Blob(blob) = value {
            if let Ok(id) = ID::try_from(blob) {
                return Ok(id);
            }
        }
        Err(FromSqlError::InvalidType)
    }
}

impl ToSql for ID {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(ValueRef::Blob(self.as_ref())))
    }
}

impl Debug for ID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl Display for ID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    id: ID,
    pub(crate) deps: Deps,
    author: PeerID,
    sign: ed25519::Signature,
    data: Bytes,
}

impl Patch {
    pub fn new<D, B>(key: &SigningKey, deps: D, data: B) -> Result<Self>
    where
        D: IntoIterator<Item = ID>,
        B: Into<Bytes>,
    {
        let data = data.into();
        let sign = key.sign(&data);
        let author = key.verifying_key().to_bytes();
        let deps = Deps::from_iter(deps);
        let mut record = Patch {
            id: ID::default(),
            author,
            sign,
            deps,
            data,
        };
        record.id = record.hash();
        Ok(record)
    }

    /// - 0: ID
    /// - 1: PeerID
    /// - 2: signature
    /// - 3: data blob
    /// - 4: deps
    pub fn from_sql_row(row: &Row) -> std::result::Result<Self, rusqlite::Error> {
        let id: ID = row.get(0)?;
        let author: PeerID = row.get(1)?;
        let sign = row.get_ref(2)?;
        let data = row.get_ref(3)?;
        let deps = row.get_ref(4);

        let signature_bytes = sign.as_bytes()?;
        let signature = signature_bytes
            .try_into()
            .map_err(|_| FromSqlError::InvalidBlobSize {
                expected_size: 64,
                blob_size: signature_bytes.len(),
            })?;
        let deps: Deps = match deps {
            Ok(deps) => {
                serde_json::from_slice(&deps.as_bytes()?).map_err(|_| FromSqlError::InvalidType)?
            }
            Err(_) => Deps::default(),
        };
        Ok(Patch {
            id,
            author,
            sign: Signature::from_bytes(&signature),
            deps,
            data: Bytes::copy_from_slice(data.as_blob()?),
        })
    }

    pub fn id(&self) -> &ID {
        &self.id
    }

    pub fn deps(&self) -> &Deps {
        &self.deps
    }

    pub fn author(&self) -> &PeerID {
        &self.author
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn sign(&self) -> &Signature {
        &self.sign
    }

    fn hash(&self) -> ID {
        let mut h = blake3::Hasher::new();
        h.update(&self.author);
        for parent in self.deps.iter() {
            h.update(parent);
        }
        h.update(&self.data);
        h.finalize().into()
    }

    pub fn verify(&self) -> std::result::Result<(), SignatureError> {
        let verifier = VerifyingKey::from_bytes(&self.author)?;
        verifier.verify(&self.data, &self.sign)
    }

    pub fn write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_u32_varint(self.deps.len() as u32)?;
        w.write_u32_varint(self.data.len() as u32)?;
        w.write_all(self.sign.r_bytes())?;
        w.write_all(self.sign.s_bytes())?;
        w.write_all(&self.author)?;
        for parent in self.deps.iter() {
            w.write_all(parent)?;
        }
        w.write_all(&self.data)?;
        Ok(())
    }

    pub fn read<R: Read>(r: &mut R) -> Result<Self> {
        let deps_len = r.read_u32_varint()? as usize;
        let data_len = r.read_u32_varint()? as usize;
        let mut r_bytes = ComponentBytes::default();
        let mut s_bytes = ComponentBytes::default();
        r.read_exact(&mut r_bytes)?;
        r.read_exact(&mut s_bytes)?;
        let mut record = Patch {
            id: ID::default(),
            deps: Deps::with_capacity(deps_len),
            author: PeerID::default(),
            sign: ed25519::Signature::from_components(r_bytes, s_bytes),
            data: Bytes::default(),
        };
        r.read_exact(&mut record.author)?;
        for _ in 0..deps_len {
            let mut parent = ID::default();
            r.read_exact(&mut parent)?;
            record.deps.insert(parent);
        }
        let mut data = Vec::with_capacity(data_len);
        unsafe { data.set_len(data_len) };
        r.read_exact(&mut data)?;
        record.data = Bytes::from(data);
        record.id = record.hash();
        Ok(record)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Deps(SmallVec<[ID; 1]>);

impl Deref for Deps {
    type Target = [ID];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl Eq for Deps {}
impl PartialEq for Deps {
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        for id in other.iter() {
            if !self.contains(id) {
                return false;
            }
        }
        return true;
    }
}

impl FromIterator<ID> for Deps {
    fn from_iter<T: IntoIterator<Item = ID>>(iter: T) -> Self {
        let mut v = SmallVec::from_iter(iter);
        v.dedup();
        Deps(v)
    }
}

impl IntoIterator for Deps {
    type Item = ID;
    type IntoIter = smallvec::IntoIter<[ID; 1]>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Deps {
    pub fn new(deps: SmallVec<[ID; 1]>) -> Self {
        Deps(deps)
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Deps(SmallVec::with_capacity(capacity))
    }

    pub fn insert(&mut self, value: ID) -> bool {
        if self.contains(&value) {
            false
        } else {
            self.0.push(value);
            true
        }
    }

    pub fn contains(&self, value: &ID) -> bool {
        self.0.iter().any(|id| id == value)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, ID> {
        self.0.iter()
    }
}

#[cfg(test)]
mod test {
    use crate::patch::{Deps, Patch};
    use ed25519_dalek::SigningKey;
    use std::io::Cursor;

    #[test]
    fn serialize_record() {
        let data = "hello world";
        let key_pair = SigningKey::generate(&mut rand::rngs::OsRng);
        let record = Patch::new(&key_pair, Deps::default(), data).unwrap();
        record.verify().unwrap();

        let mut bytes = Vec::new();
        record.write(&mut bytes).unwrap();
        let mut cursor = Cursor::new(bytes);
        let deserialized = Patch::read(&mut cursor).unwrap();
        deserialized.verify().unwrap();
        assert_eq!(record, deserialized);
    }
}
