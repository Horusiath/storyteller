use crate::PeerID;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

/// Enabled operations, defined in order from highest to lowest precedence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Op {
    /// Revoke all moderator rights and stabilize document state at the current point in time
    /// defined by PatchID. This technically has the same precedence as TransferOwnership, but it's
    /// impossible for these two operations to happen concurrently, since they both can only be
    /// invoked by current owner.
    Prune,
    /// Change document owner (first write wins).
    TransferOwnership(PeerID),
    /// Revoke moderator rights.
    Revoke(PeerID),
    /// Grant moderator rights.
    Grant(PeerID),
    /// Update key-value pair of a Map.
    UpdateEntry(String, Value),
    /// Insert an array element.
    InsertRange(u64, Vec<Value>),
    /// Remove a range of array elements.
    RemoveRange(u64, u64),
}
