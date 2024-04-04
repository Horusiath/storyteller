use ed25519_dalek::SigningKey;
use serde::Serialize;

use crate::patch::{Patch, ID};
use crate::store::ObjectStore;
use crate::{PeerID, Result};

#[derive(Debug)]
pub struct Peer<S> {
    signing_key: SigningKey,
    store: S,
    heads: Vec<ID>,
}

impl<S: ObjectStore> Peer<S> {
    pub fn new(signing_key: SigningKey, store: S) -> Result<Self> {
        let heads = store.heads()?;
        Ok(Peer {
            signing_key,
            store,
            heads,
        })
    }

    pub fn peer_id(&self) -> PeerID {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn heads(&self) -> &[ID] {
        self.heads.as_slice()
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn commit<B>(&mut self, data: &B) -> Result<Patch>
    where
        B: Serialize,
    {
        let patch = Patch::new(&self.signing_key, self.heads().iter().cloned(), data)?;
        self.store.commit(&patch)?;
        self.heads = vec![*patch.id()];
        return Ok(patch);
    }

    pub fn integrate<I>(&mut self, patches: I) -> Result<Vec<ID>>
    where
        I: IntoIterator<Item = Patch>,
    {
        let mut changed = false;
        let mut missing = Vec::new();
        let mut patches: Box<dyn Iterator<Item = Patch>> = Box::new(patches.into_iter());
        loop {
            for patch in patches {
                patch.verify()?;
                if !self.store.contains(patch.id())? {
                    let mut stashed = false;
                    for dep in patch.deps().iter() {
                        if !self.store.is_integrated(dep)? {
                            self.store.stash(&patch)?;
                            if !missing.contains(dep) {
                                missing.push(*dep);
                            }
                            stashed = true;
                        }
                    }

                    if !stashed {
                        self.store.commit(&patch)?;
                        changed = true;
                    }
                }
            }

            if changed {
                changed = false;
                self.heads = self.store.heads()?;
                patches = Box::new(self.store.unstash()?.into_iter());
            } else {
                break;
            }
        }

        Ok(missing)
    }

    pub fn missing(&self, heads: &[ID]) -> Result<Vec<ID>> {
        let mut missing = Vec::with_capacity(heads.len());
        for id in heads.iter() {
            if !self.store.contains(id)? {
                missing.push(*id);
            }
        }
        Ok(missing)
    }

    pub fn patches(&self, ids: &[ID]) -> Result<Vec<Patch>> {
        self.store.patches(ids)
    }
}

#[cfg(test)]
mod test {
    use ed25519_dalek::SigningKey;

    use crate::patch::Patch;
    use crate::peer::Peer;
    use crate::store::sqlite::SqliteStore;

    fn create_peer() -> Peer<SqliteStore> {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let store = SqliteStore::new(conn).unwrap();
        let key_pair = SigningKey::generate(&mut rand::rngs::OsRng);
        Peer::new(key_pair, store).unwrap()
    }

    /// ```no_compile
    ///      / B - D
    ///     A    \
    ///      \ C - E - F
    /// ```
    pub fn init_patches(p: &Peer<SqliteStore>) -> Vec<Patch> {
        let a = Patch::new(&p.signing_key, [], &"A").unwrap();
        let b = Patch::new(&p.signing_key, [*a.id()], &"B").unwrap();
        let c = Patch::new(&p.signing_key, [*a.id()], &"C").unwrap();
        let d = Patch::new(&p.signing_key, [*b.id()], &"D").unwrap();
        let e = Patch::new(&p.signing_key, [*b.id(), *c.id()], &"E").unwrap();
        let f = Patch::new(&p.signing_key, [*e.id()], &"F").unwrap();

        vec![a, b, c, d, e, f]
    }

    fn run_reconcile(src: &Peer<SqliteStore>, dst: &mut Peer<SqliteStore>) {
        let heads = src.heads();
        let mut missing = dst.missing(heads).unwrap();
        while !missing.is_empty() {
            let patches = src.patches(&missing).unwrap();
            missing = dst.integrate(patches).unwrap()
        }
    }

    #[test]
    fn reconcile() {
        let mut p1 = create_peer();
        let mut p2 = create_peer();
        let patches = init_patches(&p1);
        p1.integrate(patches.clone()).unwrap();
        p2.integrate(patches.clone()).unwrap();
        let g = p1.commit(&"G").unwrap();
        let h = p2.commit(&"H").unwrap();
        let i = p2.commit(&"I").unwrap();

        // reconcile
        run_reconcile(&p1, &mut p2);
        run_reconcile(&p2, &mut p1);

        let mut ids: Vec<_> = patches.into_iter().map(|p| *p.id()).collect();
        ids.push(*g.id());
        ids.push(*h.id());
        ids.push(*i.id());
        let res1 = p1.patches(&*ids).unwrap();
        let res2 = p1.patches(&*ids).unwrap();
        assert_eq!(res1, res2);
    }
    #[test]
    fn commit() {
        let mut peer = create_peer();
        let patches = init_patches(&peer);
        let ids: Vec<_> = patches.iter().map(|p| *p.id()).collect();

        let missing = peer.integrate(patches.clone()).unwrap();
        let in_store = peer.patches(&ids).unwrap();

        assert_eq!(patches, in_store);
        assert!(missing.is_empty());
    }

    #[test]
    fn missing_dep() {
        let mut peer = create_peer();
        let mut patches = init_patches(&peer);
        let ids: Vec<_> = patches.iter().map(|p| *p.id()).collect();

        let removed = patches.remove(4);
        let missing = peer.integrate(patches.clone()).unwrap();
        assert_eq!(missing, vec![*removed.id()]);

        let in_store: Vec<_> = peer
            .patches(&ids)
            .unwrap()
            .into_iter()
            .map(|p| serde_json::from_slice::<String>(p.data()).unwrap())
            .collect();
        assert_eq!(in_store, vec!["A", "B", "C", "D"]);
    }
}
