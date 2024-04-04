use crate::patch::{Deps, Patch, ID};
use crate::store::ObjectStore;
use crate::Result;
use rusqlite::params;
use smallvec::SmallVec;

pub struct SqliteStore {
    conn: rusqlite::Connection,
}

impl SqliteStore {
    pub fn new(conn: rusqlite::Connection) -> Result<Self> {
        Self::with_options(conn, Options::default())
    }

    pub fn with_options(conn: rusqlite::Connection, options: Options) -> Result<Self> {
        Self::init_schema(&conn)?;
        Ok(SqliteStore { conn })
    }

    fn init_schema(conn: &rusqlite::Connection) -> Result<()> {
        conn.execute_batch(
            r#"
        CREATE TABLE IF NOT EXISTS st_authors(
            author_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            verification_key BLOB NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS st_patches(
            seq_no INTEGER PRIMARY KEY AUTOINCREMENT,
            hash BLOB NOT NULL UNIQUE CHECK(LENGTH(hash) = 32),
            author_id BLOB NOT NULL,
            signature BLOB NOT NULL CHECK(LENGTH(signature) = 64),
            data JSONB,
            FOREIGN KEY (author_id) REFERENCES st_authors(author_id)
        );
        CREATE TABLE IF NOT EXISTS st_stash(
            seq_no INTEGER PRIMARY KEY AUTOINCREMENT,
            deps JSONB NOT NULL,
            hash BLOB NOT NULL UNIQUE CHECK(LENGTH(hash) = 32),
            author BLOB NOT NULL CHECK(LENGTH(author) = 32),
            signature BLOB NOT NULL CHECK(LENGTH(signature) = 64),
            data JSONB
        );
        CREATE UNIQUE INDEX IF NOT EXISTS uq_st_stash_hash ON st_stash(hash);
        CREATE TABLE IF NOT EXISTS st_rel(
            child INTEGER,
            parent INTEGER,
            PRIMARY KEY (child, parent),
            FOREIGN KEY (child) REFERENCES st_patches(seq_no),
            FOREIGN KEY (parent) REFERENCES st_patches(seq_no)
        )"#,
        )?;
        Ok(())
    }
}

impl ObjectStore for SqliteStore {
    fn heads(&self) -> Result<Vec<ID>> {
        let mut stmt = self.conn.prepare(
            r#"
        SELECT hash
        FROM st_patches
        WHERE seq_no NOT IN (SELECT child FROM st_rel)"#,
        )?;
        let mut heads = Vec::new();
        for head in stmt.query_map((), |row| row.get(0))? {
            heads.push(head?);
        }
        Ok(heads)
    }

    fn patches(&self, ids: &[ID]) -> Result<Vec<Patch>> {
        let mut patches = Vec::with_capacity(ids.len());
        let mut patch_stmt = self.conn.prepare(
            r#"
            SELECT p.hash, a.verification_key as author, p.signature, p.data
            FROM st_patches p
            JOIN st_authors a ON p.author_id = a.author_id
            WHERE hash = ?"#,
        )?;
        let mut deps_stmt = self.conn.prepare(
            r#"
        SELECT parent.hash
        FROM st_patches parent
        JOIN st_rel r ON parent.seq_no = r.parent
        JOIN st_patches child ON child.seq_no = r.child
        WHERE child.hash = ?"#,
        )?;
        for id in ids.iter() {
            if let Some(mut patch) = patch_stmt
                .query_row(params![id], Patch::from_sql_row)
                .found()?
            {
                let parents = deps_stmt.query_map(params![id], |row| row.get::<_, ID>(0))?;
                let mut deps = SmallVec::default();
                for parent in parents {
                    deps.push(parent?);
                }
                patch.deps = Deps::new(deps);
                patches.push(patch);
            }
        }
        Ok(patches)
    }

    fn is_integrated(&self, patch_id: &ID) -> Result<bool> {
        let mut stmt = self.conn.prepare(
            r#"
        SELECT 1
        FROM st_patches
        WHERE hash = ?"#,
        )?;
        let res = stmt.query_row(params![patch_id], |_| Ok(()));
        match res {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn contains(&self, patch_id: &ID) -> Result<bool> {
        let mut stmt = self.conn.prepare(
            r#"
        SELECT 1 FROM st_patches WHERE hash = ?
        UNION
        SELECT 1 FROM st_stash WHERE hash = ?"#,
        )?;
        let res = stmt.query_row(params![patch_id, patch_id], |_| Ok(()));
        match res {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn commit(&self, patch: &Patch) -> Result<()> {
        let hash = patch.id();
        let author = patch.author();
        let sign = patch.sign().to_bytes();
        let data = patch.data();
        let author_id =
            self.conn.query_row(r#"SElECT author_id FROM st_authors WHERE verification_key = ?"#, params![author], |row| row.get::<_, u32>(0)).or_else(|_|
            self.conn.query_row(r#"INSERT INTO st_authors(verification_key) VALUES(?) ON CONFLICT (verification_key) DO NOTHING RETURNING author_id"#, params![author], |row| row.get::<_, u32>(0)))?;
        let patch_id = self.conn.query_row(
            r#"INSERT INTO st_patches(hash, author_id, signature, data) VALUES (?, ?, ?, ?) RETURNING seq_no"#,
            params![hash, author_id, sign, data],
            |row| row.get::<_, u64>(0)
        )?;
        for parent in patch.deps().iter() {
            self.conn.execute(
                r#"
            INSERT INTO st_rel(parent, child)
            VALUES((SELECT seq_no FROM st_patches WHERE hash = ?), ?)
            "#,
                params![parent, patch_id],
            )?;
        }
        Ok(())
    }

    fn stash(&self, patch: &Patch) -> Result<()> {
        let hash = patch.id();
        let author = patch.author();
        let sign = patch.sign().to_bytes();
        let deps = serde_json::to_vec(patch.deps())?;
        let data = patch.data();
        self.conn.execute(
            r#"
        INSERT INTO st_stash(hash, signature, deps, data, author)
        VALUES (?, ?, ?, ?, ?)"#,
            params![hash, sign, deps, data, author],
        )?;
        Ok(())
    }

    fn unstash(&self) -> Result<Vec<Patch>> {
        let mut stmt = self
            .conn
            .prepare(r#"SELECT hash, author, signature, data, deps FROM st_stash"#)?;
        let patches: Vec<_> = stmt
            .query_map((), |row| match Patch::from_sql_row(row) {
                Ok(patch) => Ok(patch),
                Err(e) => Err(rusqlite::Error::ToSqlConversionFailure(e.into())),
            })?
            .map(|patch| patch.unwrap())
            .collect();
        self.conn.execute("DELETE FROM st_stash", ())?;
        Ok(patches)
    }
}

#[derive(Debug, Clone)]
pub struct Options {}

impl Default for Options {
    fn default() -> Self {
        Options {}
    }
}

trait Found {
    type Item;
    type Error;
    fn found(self) -> std::result::Result<Option<Self::Item>, Self::Error>;
}

impl<T> Found for std::result::Result<T, rusqlite::Error> {
    type Item = T;
    type Error = rusqlite::Error;

    #[inline]
    fn found(self) -> std::result::Result<Option<Self::Item>, Self::Error> {
        match self {
            Ok(item) => Ok(Some(item)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(other) => Err(other),
        }
    }
}
