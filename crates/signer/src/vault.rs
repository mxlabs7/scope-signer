//! Coffre du signer : clés de wallets chiffrées, dans un stockage local propre au signer.
//!
//! - Chiffrement XChaCha20-Poly1305 avec la clé maître (32 octets), nonce aléatoire par wallet.
//! - Chaque chiffré est LIÉ à son wallet et à son propriétaire (données associées) :
//!   échanger deux entrées dans le fichier rend le déchiffrement impossible.
//! - Une « valeur de contrôle » détecte une mauvaise clé maître dès l'ouverture.
//! - Le fichier ne contient que des chiffrés : il peut être sauvegardé tel quel.

use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use sha2::Sha256;
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, Zeroizing};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// Clé publique du wallet → enregistrement chiffré.
const WALLETS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("wallets");
/// (utilisateur ‖ id de credential) → `[4 : compteur][clé COSE]`. Registre de référence des passkeys.
const PASSKEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("passkeys");
/// (utilisateur ‖ empreinte du code) → `[1 : utilisé ?]`. Codes de secours.
const RECOVERY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("recovery");
/// utilisateur → `[8 : dernier pas utilisé][secret TOTP chiffré]`. Code d'appli (retraits Telegram).
const TOTP: TableDefinition<&[u8], &[u8]> = TableDefinition::new("totp");
const TOTP_AAD: &[u8] = b"scope-totp-v1";

const CHECK_KEY: &str = "master_key_check";
const CHECK_PLAIN: &[u8] = b"scope-vault-v1";
const WALLET_AAD: &[u8] = b"scope-wallet-v1";

/// Clé maître : n'existe qu'en mémoire, effacée à la destruction.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&Key::from(*self.0))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    /// La clé maître ne correspond pas à ce coffre.
    WrongMasterKey,
    /// Ce wallet existe déjà dans le coffre.
    AlreadyExists,
    /// Wallet inconnu, ou n'appartenant pas à cet utilisateur.
    NotFound,
    /// Clé privée importée invalide.
    InvalidKey,
    Storage(String),
    Crypto,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for VaultError {}

fn storage<E: std::fmt::Display>(e: E) -> VaultError {
    VaultError::Storage(e.to_string())
}

pub struct Vault {
    db: Database,
    master: MasterKey,
}

/// Enregistrement : `[16 octets : id utilisateur][24 : nonce][chiffré de la graine de 32 octets + tag]`.
const USER_LEN: usize = 16;
const NONCE_LEN: usize = 24;

impl Vault {
    /// Ouvre (ou crée) le coffre. Refuse une clé maître qui ne correspond pas.
    pub fn open(path: &Path, master: MasterKey) -> Result<Self, VaultError> {
        let db = Database::create(path).map_err(storage)?;
        let vault = Self { db, master };
        vault.check_or_init()?;
        Ok(vault)
    }

    fn check_or_init(&self) -> Result<(), VaultError> {
        let existing = {
            let read = self.db.begin_read().map_err(storage)?;
            match read.open_table(META) {
                Ok(t) => t
                    .get(CHECK_KEY)
                    .map_err(storage)?
                    .map(|v| v.value().to_vec()),
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(e) => return Err(storage(e)),
            }
        };
        match existing {
            Some(blob) => {
                let plain = self
                    .decrypt(&blob, CHECK_PLAIN)
                    .map_err(|_| VaultError::WrongMasterKey)?;
                if plain.as_slice() == CHECK_PLAIN {
                    Ok(())
                } else {
                    Err(VaultError::WrongMasterKey)
                }
            }
            None => {
                let blob = self.encrypt(CHECK_PLAIN, CHECK_PLAIN)?;
                let write = self.db.begin_write().map_err(storage)?;
                {
                    let mut meta = write.open_table(META).map_err(storage)?;
                    meta.insert(CHECK_KEY, blob.as_slice()).map_err(storage)?;
                    write.open_table(WALLETS).map_err(storage)?;
                    write.open_table(PASSKEYS).map_err(storage)?;
                    write.open_table(RECOVERY).map_err(storage)?;
                    write.open_table(TOTP).map_err(storage)?;
                }
                write.commit().map_err(storage)
            }
        }
    }

    fn encrypt(&self, plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| VaultError::Crypto)?;
        let ct = self
            .master
            .cipher()
            .encrypt(&XNonce::from(nonce), Payload { msg: plain, aad })
            .map_err(|_| VaultError::Crypto)?;
        Ok([nonce.as_slice(), &ct].concat())
    }

    fn decrypt(&self, blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if blob.len() < NONCE_LEN {
            return Err(VaultError::Crypto);
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| VaultError::Crypto)?;
        self.master
            .cipher()
            .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| VaultError::Crypto)
    }

    /// Clé de transport X25519 du signer, dérivée de la clé maître : stable entre les redémarrages,
    /// sans aucun secret supplémentaire à sauvegarder.
    pub fn transport_secret(&self) -> Result<StaticSecret, VaultError> {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, self.master.0.as_slice())
            .expand(b"scope-transport-v1", key.as_mut())
            .map_err(|_| VaultError::Crypto)?;
        Ok(StaticSecret::from(*key))
    }

    fn wallet_aad(pubkey: &[u8; 32], user: &[u8; USER_LEN]) -> Vec<u8> {
        [WALLET_AAD, pubkey.as_slice(), user.as_slice()].concat()
    }

    fn store(&self, user: &[u8; USER_LEN], key: &SigningKey) -> Result<[u8; 32], VaultError> {
        let pubkey = key.verifying_key().to_bytes();
        let seed = Zeroizing::new(key.to_bytes());
        let blob = self.encrypt(seed.as_slice(), &Self::wallet_aad(&pubkey, user))?;
        let record = [user.as_slice(), &blob].concat();

        let write = self.db.begin_write().map_err(storage)?;
        {
            let mut wallets = write.open_table(WALLETS).map_err(storage)?;
            if wallets.get(&pubkey).map_err(storage)?.is_some() {
                return Err(VaultError::AlreadyExists);
            }
            wallets
                .insert(&pubkey, record.as_slice())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(pubkey)
    }

    /// Crée un wallet. Renvoie sa clé publique et sa graine (à afficher UNE fois à l'utilisateur).
    pub fn create_wallet(
        &self,
        user: &[u8; USER_LEN],
    ) -> Result<([u8; 32], Zeroizing<[u8; 32]>), VaultError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| VaultError::Crypto)?;
        let key = SigningKey::from_bytes(&seed);
        let pubkey = self.store(user, &key)?;
        Ok((pubkey, seed))
    }

    /// Importe un wallet existant. Accepte la clé au format Solana (64 octets : graine + clé publique,
    /// la clé publique est alors vérifiée) ou la graine seule (32 octets).
    pub fn import_wallet(
        &self,
        user: &[u8; USER_LEN],
        secret: &[u8],
    ) -> Result<[u8; 32], VaultError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        match secret.len() {
            32 | 64 => seed.copy_from_slice(&secret[..32]),
            _ => return Err(VaultError::InvalidKey),
        }
        let key = SigningKey::from_bytes(&seed);
        if secret.len() == 64 && key.verifying_key().as_bytes() != &secret[32..] {
            return Err(VaultError::InvalidKey);
        }
        self.store(user, &key)
    }

    /// Clé de signature d'un wallet, seulement pour son propriétaire.
    pub fn signing_key(
        &self,
        user: &[u8; USER_LEN],
        pubkey: &[u8; 32],
    ) -> Result<SigningKey, VaultError> {
        let read = self.db.begin_read().map_err(storage)?;
        let wallets = read.open_table(WALLETS).map_err(storage)?;
        let record = wallets
            .get(pubkey)
            .map_err(storage)?
            .ok_or(VaultError::NotFound)?;
        let record = record.value();
        if record.len() < USER_LEN || &record[..USER_LEN] != user.as_slice() {
            return Err(VaultError::NotFound);
        }
        let mut seed = self.decrypt(&record[USER_LEN..], &Self::wallet_aad(pubkey, user))?;
        let bytes: [u8; 32] = seed.as_slice().try_into().map_err(|_| VaultError::Crypto)?;
        seed.zeroize();
        Ok(SigningKey::from_bytes(&bytes))
    }

    /// Clés publiques de tous les wallets d'un utilisateur.
    pub fn wallets_of(&self, user: &[u8; USER_LEN]) -> Result<Vec<[u8; 32]>, VaultError> {
        let read = self.db.begin_read().map_err(storage)?;
        let wallets = read.open_table(WALLETS).map_err(storage)?;
        let mut out = Vec::new();
        for entry in wallets.iter().map_err(storage)? {
            let (k, v) = entry.map_err(storage)?;
            if v.value().get(..USER_LEN) == Some(user.as_slice()) {
                out.push(*k.value());
            }
        }
        Ok(out)
    }
}

/// Code d'appli (TOTP) du registre : secret déchiffré (effacé de la mémoire après usage) et dernier
/// pas utilisé (anti-rejeu).
pub struct StoredTotp {
    pub secret: Zeroizing<Vec<u8>>,
    pub last_step: u64,
}

/// Passkey du registre.
pub struct StoredPasskey {
    pub credential_id: Vec<u8>,
    pub cose: Vec<u8>,
    pub counter: u32,
}

fn prefixed(user: &[u8; USER_LEN], rest: &[u8]) -> Vec<u8> {
    [user.as_slice(), rest].concat()
}

type BytesTable = redb::ReadOnlyTable<&'static [u8], &'static [u8]>;

/// Lit une table, en la considérant vide si elle n'existe pas encore (coffre créé avant son ajout).
fn read_table(
    read: &redb::ReadTransaction,
    def: TableDefinition<&'static [u8], &'static [u8]>,
) -> Result<Option<BytesTable>, VaultError> {
    match read.open_table(def) {
        Ok(t) => Ok(Some(t)),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(e) => Err(storage(e)),
    }
}

impl Vault {
    /// Passkeys enregistrées pour cet utilisateur.
    pub fn passkeys(&self, user: &[u8; USER_LEN]) -> Result<Vec<StoredPasskey>, VaultError> {
        let read = self.db.begin_read().map_err(storage)?;
        let Some(table) = read_table(&read, PASSKEYS)? else {
            return Ok(vec![]);
        };
        let mut out = Vec::new();
        for entry in table.range::<&[u8]>(user.as_slice()..).map_err(storage)? {
            let (k, v) = entry.map_err(storage)?;
            let (k, v) = (k.value(), v.value());
            if !k.starts_with(user) {
                break;
            }
            if v.len() < 4 {
                return Err(VaultError::Crypto);
            }
            out.push(StoredPasskey {
                credential_id: k[USER_LEN..].to_vec(),
                counter: u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
                cose: v[4..].to_vec(),
            });
        }
        Ok(out)
    }

    /// Ajoute une passkey, ou met à jour son compteur.
    pub fn put_passkey(&self, user: &[u8; USER_LEN], p: &StoredPasskey) -> Result<(), VaultError> {
        let write = self.db.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(PASSKEYS).map_err(storage)?;
            let value = [p.counter.to_be_bytes().as_slice(), &p.cose].concat();
            table
                .insert(
                    prefixed(user, &p.credential_id).as_slice(),
                    value.as_slice(),
                )
                .map_err(storage)?;
        }
        write.commit().map_err(storage)
    }

    /// Remplace TOUS les codes de secours de l'utilisateur par ces empreintes.
    pub fn set_recovery(
        &self,
        user: &[u8; USER_LEN],
        hashes: &[[u8; 32]],
    ) -> Result<(), VaultError> {
        let write = self.db.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(RECOVERY).map_err(storage)?;
            let old: Vec<Vec<u8>> = table
                .range::<&[u8]>(user.as_slice()..)
                .map_err(storage)?
                .filter_map(Result::ok)
                .map(|(k, _)| k.value().to_vec())
                .take_while(|k| k.starts_with(user))
                .collect();
            for k in old {
                table.remove(k.as_slice()).map_err(storage)?;
            }
            for h in hashes {
                table
                    .insert(prefixed(user, h).as_slice(), [0u8].as_slice())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)
    }

    /// Consomme un code de secours (par son empreinte). Vrai s'il existait et n'avait pas servi.
    pub fn consume_recovery(
        &self,
        user: &[u8; USER_LEN],
        hash: &[u8; 32],
    ) -> Result<bool, VaultError> {
        let write = self.db.begin_write().map_err(storage)?;
        let ok = {
            let mut table = write.open_table(RECOVERY).map_err(storage)?;
            let key = prefixed(user, hash);
            let unused = table
                .get(key.as_slice())
                .map_err(storage)?
                .is_some_and(|v| v.value() == [0u8]);
            if unused {
                table
                    .insert(key.as_slice(), [1u8].as_slice())
                    .map_err(storage)?;
            }
            unused
        };
        write.commit().map_err(storage)?;
        Ok(ok)
    }

    /// Code d'appli de l'utilisateur, s'il en a un.
    pub fn totp(&self, user: &[u8; USER_LEN]) -> Result<Option<StoredTotp>, VaultError> {
        let read = self.db.begin_read().map_err(storage)?;
        let Some(table) = read_table(&read, TOTP)? else {
            return Ok(None);
        };
        let Some(v) = table.get(user.as_slice()).map_err(storage)? else {
            return Ok(None);
        };
        let v = v.value();
        if v.len() < 8 {
            return Err(VaultError::Crypto);
        }
        let last = u64::from_be_bytes(v[..8].try_into().map_err(|_| VaultError::Crypto)?);
        let secret = self.decrypt(&v[8..], &[TOTP_AAD, user.as_slice()].concat())?;
        Ok(Some(StoredTotp {
            secret,
            last_step: last,
        }))
    }

    /// Enregistre (ou remplace) le code d'appli de l'utilisateur.
    pub fn set_totp(
        &self,
        user: &[u8; USER_LEN],
        secret: &[u8],
        last_step: u64,
    ) -> Result<(), VaultError> {
        let blob = self.encrypt(secret, &[TOTP_AAD, user.as_slice()].concat())?;
        let value = [last_step.to_be_bytes().as_slice(), &blob].concat();
        let write = self.db.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(TOTP).map_err(storage)?;
            table
                .insert(user.as_slice(), value.as_slice())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)
    }

    /// Le compte a-t-il déjà un facteur (passkey, code d'appli ou codes de secours) dans le registre ?
    pub fn has_factors(&self, user: &[u8; USER_LEN]) -> Result<bool, VaultError> {
        if !self.passkeys(user)?.is_empty() || self.totp(user)?.is_some() {
            return Ok(true);
        }
        let read = self.db.begin_read().map_err(storage)?;
        let Some(table) = read_table(&read, RECOVERY)? else {
            return Ok(false);
        };
        let first = table
            .range::<&[u8]>(user.as_slice()..)
            .map_err(storage)?
            .next();
        Ok(match first {
            Some(entry) => entry.map_err(storage)?.0.value().starts_with(user),
            None => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, Verifier as _};

    const ALICE: [u8; 16] = [1; 16];
    const BOB: [u8; 16] = [2; 16];

    fn key(b: u8) -> MasterKey {
        MasterKey::from_bytes([b; 32])
    }

    fn tmp() -> Result<tempfile::TempDir, std::io::Error> {
        tempfile::tempdir()
    }

    #[test]
    fn cree_un_wallet_et_le_retrouve_apres_reouverture() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tmp()?;
        let path = dir.path().join("vault.redb");
        let (pubkey, seed) = Vault::open(&path, key(7))?.create_wallet(&ALICE)?;
        // Le coffre est fermé puis rouvert (redémarrage du signer) : le wallet est intact.
        let vault = Vault::open(&path, key(7))?;
        let sk = vault.signing_key(&ALICE, &pubkey)?;
        assert_eq!(sk.to_bytes(), *seed);
        let sig = sk.sign(b"tx");
        assert!(sk.verifying_key().verify(b"tx", &sig).is_ok());
        assert_eq!(vault.wallets_of(&ALICE)?, vec![pubkey]);
        Ok(())
    }

    #[test]
    fn refuse_une_mauvaise_cle_maitre() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tmp()?;
        let path = dir.path().join("vault.redb");
        Vault::open(&path, key(7))?.create_wallet(&ALICE)?;
        assert!(matches!(
            Vault::open(&path, key(8)),
            Err(VaultError::WrongMasterKey)
        ));
        Ok(())
    }

    #[test]
    fn un_wallet_n_est_accessible_qu_a_son_proprietaire() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tmp()?;
        let vault = Vault::open(&dir.path().join("v.redb"), key(7))?;
        let (pubkey, _) = vault.create_wallet(&ALICE)?;
        assert!(matches!(
            vault.signing_key(&BOB, &pubkey),
            Err(VaultError::NotFound)
        ));
        assert!(vault.wallets_of(&BOB)?.is_empty());
        Ok(())
    }

    #[test]
    fn le_fichier_ne_contient_jamais_la_cle_en_clair() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tmp()?;
        let path = dir.path().join("v.redb");
        let (_, seed) = Vault::open(&path, key(7))?.create_wallet(&ALICE)?;
        let raw = std::fs::read(&path)?;
        assert!(!raw.windows(32).any(|w| w == seed.as_slice()));
        Ok(())
    }

    /// Un pirate qui modifie le fichier pour s'attribuer le wallet d'Alice ne peut pas le déchiffrer.
    #[test]
    fn un_enregistrement_detourne_ne_se_dechiffre_pas() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tmp()?;
        let vault = Vault::open(&dir.path().join("v.redb"), key(7))?;
        let (pubkey, _) = vault.create_wallet(&ALICE)?;
        {
            let write = vault.db.begin_write()?;
            {
                let mut t = write.open_table(WALLETS)?;
                let rec = t
                    .get(&pubkey)?
                    .map(|v| v.value().to_vec())
                    .ok_or("absent")?;
                let forged = [BOB.as_slice(), &rec[USER_LEN..]].concat();
                t.insert(&pubkey, forged.as_slice())?;
            }
            write.commit()?;
        }
        assert!(matches!(
            vault.signing_key(&BOB, &pubkey),
            Err(VaultError::Crypto)
        ));
        Ok(())
    }

    #[test]
    fn registre_des_passkeys_et_codes_de_secours() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tmp()?;
        let path = dir.path().join("v.redb");
        let vault = Vault::open(&path, key(7))?;
        assert!(!vault.has_factors(&ALICE)?);
        vault.put_passkey(
            &ALICE,
            &StoredPasskey {
                credential_id: vec![1, 2],
                cose: vec![9; 10],
                counter: 0,
            },
        )?;
        vault.set_recovery(&ALICE, &[[1; 32], [2; 32]])?;
        assert!(vault.has_factors(&ALICE)?);
        assert!(!vault.has_factors(&BOB)?);
        // Compteur mis à jour, isolé par utilisateur, et persistant après réouverture.
        vault.put_passkey(
            &ALICE,
            &StoredPasskey {
                credential_id: vec![1, 2],
                cose: vec![9; 10],
                counter: 5,
            },
        )?;
        drop(vault);
        let vault = Vault::open(&path, key(7))?;
        let pks = vault.passkeys(&ALICE)?;
        assert_eq!((pks.len(), pks[0].counter), (1, 5));
        assert!(vault.passkeys(&BOB)?.is_empty());
        // Un code de secours ne sert qu'une fois ; un code de BOB n'existe pas chez ALICE.
        assert!(vault.consume_recovery(&ALICE, &[1; 32])?);
        assert!(!vault.consume_recovery(&ALICE, &[1; 32])?);
        assert!(!vault.consume_recovery(&BOB, &[2; 32])?);
        // Régénération : les anciens codes ne marchent plus.
        vault.set_recovery(&ALICE, &[[3; 32]])?;
        assert!(!vault.consume_recovery(&ALICE, &[2; 32])?);
        assert!(vault.consume_recovery(&ALICE, &[3; 32])?);
        Ok(())
    }

    #[test]
    fn importe_une_cle_solana_et_refuse_les_cles_incoherentes()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tmp()?;
        let vault = Vault::open(&dir.path().join("v.redb"), key(7))?;
        let sk = SigningKey::from_bytes(&[9; 32]);
        let solana = [sk.to_bytes().as_slice(), sk.verifying_key().as_bytes()].concat();
        assert_eq!(
            vault.import_wallet(&ALICE, &solana)?,
            sk.verifying_key().to_bytes()
        );
        // Même wallet importé deux fois (ou par quelqu'un d'autre) : refusé.
        assert_eq!(
            vault.import_wallet(&BOB, &solana),
            Err(VaultError::AlreadyExists)
        );
        // Clé publique qui ne correspond pas à la graine : refusé.
        let mut bad = solana.clone();
        bad[40] ^= 1;
        assert_eq!(
            vault.import_wallet(&ALICE, &bad),
            Err(VaultError::InvalidKey)
        );
        assert_eq!(
            vault.import_wallet(&ALICE, &[1; 10]),
            Err(VaultError::InvalidKey)
        );
        Ok(())
    }
}
