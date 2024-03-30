use crate::patch::{Patch, ID};

pub mod sqlite;

pub trait ObjectStore: Sized {
    /// Returns current heads - IDs of the most recent patches that will serve as future dependencies
    /// for newly committed patches.
    fn heads(&self) -> crate::Result<Vec<ID>>;

    /// Returns list of patches identified by their IDs.
    fn patches(&self, ids: &[ID]) -> crate::Result<Vec<Patch>>;

    /// Returns true if patch with a given ID has been successfully integrated into object store.
    fn is_integrated(&self, patch_id: &ID) -> crate::Result<bool>;

    /// Returns true if patch could be found in either object store or a list of stashed patches.
    fn contains(&self, patch_id: &ID) -> crate::Result<bool>;

    /// Commits given patch, integrating it into object store.
    fn commit(&self, patch: &Patch) -> crate::Result<()>;

    /// Stashes given patch.
    fn stash(&self, patch: &Patch) -> crate::Result<()>;

    /// Returns iterator over stashed elements, removing them from stash space.
    fn unstash(&self) -> crate::Result<Vec<Patch>>;
}
