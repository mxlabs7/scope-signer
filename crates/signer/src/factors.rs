//! Registre des facteurs d'authentification, tenu PAR LE SIGNER.
//!
//! Règle centrale : tout ce qui peut faire sortir de la valeur exige une preuve vérifiée ici,
//! jamais par l'API. Une API piratée ne peut ni ajouter sa propre passkey, ni fabriquer de codes
//! de secours, ni rejouer une ancienne validation.
//!
//! - Premier facteur d'un compte : accepté sans preuve (inévitable), et le signer génère alors les
//!   codes de secours, renvoyés scellés pour l'affichage UNIQUE à l'utilisateur.
//! - Ensuite : ajouter une passkey ou régénérer les codes exige une passkey existante (sur un défi
//!   lié à l'action + nonce à usage unique émis par le signer) ou un code de secours.
//! - Passkeys perdues : un code de secours permet d'en enregistrer une nouvelle. Jamais de fonds bloqués.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use scope_protocol::challenge;
use scope_protocol::signer_frame::{Failure, Proof, Response, UserId};
use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

use crate::seal;
use crate::totp;
use crate::vault::{StoredPasskey, Vault};
use crate::webauthn::{self, RelyingParty};

const NONCE_TTL: Duration = Duration::from_secs(300);
pub const RECOVERY_CODES: usize = 10;
/// Code d'appli préparé mais pas encore activé : valable 10 minutes.
const PENDING_TOTP_TTL: Duration = Duration::from_secs(600);
/// Anti force brute des codes d'appli : au plus 5 erreurs par 15 min et 20 par 24 h.
const TOTP_FAILS: [(usize, Duration); 2] = [
    (5, Duration::from_secs(15 * 60)),
    (20, Duration::from_secs(24 * 3600)),
];

/// Code d'appli préparé : secret et date de création.
type PendingTotp = (Zeroizing<Vec<u8>>, Instant);

pub struct Factors {
    rp: RelyingParty,
    /// Nonces émis, à usage unique : nonce → (utilisateur, émission).
    nonces: Mutex<HashMap<[u8; 32], (UserId, Instant)>>,
    /// Codes d'appli préparés, en attente du premier code : utilisateur → (secret, création).
    pending_totp: Mutex<HashMap<UserId, PendingTotp>>,
    /// Erreurs de code d'appli récentes, par utilisateur.
    totp_failures: Mutex<HashMap<UserId, Vec<Instant>>>,
}

/// Empreinte d'un code de secours (normalisé en majuscules), liée à l'utilisateur.
fn recovery_hash(user: &UserId, code: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"scope-recovery-v1\0");
    h.update(user);
    h.update(code.trim().to_ascii_uppercase().as_bytes());
    h.finalize().into()
}

/// Génère des codes « XXXXX-XXXXX » (40 bits d'aléa chacun) et leurs empreintes.
fn new_recovery_codes(user: &UserId) -> Result<(String, Vec<[u8; 32]>), Failure> {
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    for _ in 0..RECOVERY_CODES {
        let mut raw = [0u8; 5];
        getrandom::fill(&mut raw).map_err(|_| Failure::Internal)?;
        let hex: String = raw.iter().map(|b| format!("{b:02X}")).collect();
        codes.push(format!("{}-{}", &hex[..5], &hex[5..]));
    }
    let hashes = codes.iter().map(|c| recovery_hash(user, c)).collect();
    Ok((codes.join("\n"), hashes))
}

impl Factors {
    pub fn new(rp: RelyingParty) -> Self {
        Self {
            rp,
            nonces: Mutex::new(HashMap::new()),
            pending_totp: Mutex::new(HashMap::new()),
            totp_failures: Mutex::new(HashMap::new()),
        }
    }

    /// Bloqué si trop d'erreurs récentes.
    fn totp_locked(&self, user: &UserId) -> Result<bool, Failure> {
        let mut map = self.totp_failures.lock().map_err(|_| Failure::Internal)?;
        let list = map.entry(*user).or_default();
        list.retain(|t| t.elapsed() < TOTP_FAILS[1].1);
        Ok(TOTP_FAILS
            .iter()
            .any(|(max, window)| list.iter().filter(|t| t.elapsed() < *window).count() >= *max))
    }

    fn totp_failed(&self, user: &UserId) -> Result<(), Failure> {
        let mut map = self.totp_failures.lock().map_err(|_| Failure::Internal)?;
        map.entry(*user).or_default().push(Instant::now());
        Ok(())
    }

    /// Vérifie un code d'appli : anti force brute, puis code valide jamais utilisé (anti-rejeu).
    fn check_totp(&self, vault: &Vault, user: &UserId, code: &str) -> Result<(), Failure> {
        if self.totp_locked(user)? {
            return Err(Failure::Locked);
        }
        let Some(t) = vault.totp(user).map_err(|_| Failure::Internal)? else {
            return Err(Failure::BadProof);
        };
        match totp::verify(&t.secret, code, totp::now_step(), t.last_step) {
            Some(step) => vault
                .set_totp(user, &t.secret, step)
                .map_err(|_| Failure::Internal),
            None => {
                self.totp_failed(user)?;
                Err(Failure::BadProof)
            }
        }
    }

    /// Vérifie un code d'appli (connexion web).
    pub fn verify_totp(&self, vault: &Vault, user: UserId, code: &str) -> Response {
        match self.check_totp(vault, &user, code) {
            Ok(()) => Response::Ok,
            Err(f) => Response::Failed(f),
        }
    }

    /// Prépare un code d'appli : secret généré ICI, renvoyé scellé pour l'affichage unique.
    /// Si le compte a déjà un facteur, une preuve est exigée (sinon un voleur de session Telegram
    /// pourrait installer SA propre appli de codes).
    pub fn totp_setup(
        &self,
        vault: &Vault,
        user: UserId,
        seal_to: &[u8; 32],
        proof: &Proof,
    ) -> Response {
        let run = || -> Result<Response, Failure> {
            if vault.has_factors(&user).map_err(|_| Failure::Internal)? {
                self.check(vault, &user, proof, |n| {
                    challenge::challenge(challenge::ADD_TOTP, &user, &[], n)
                })?;
            }
            let mut secret = Zeroizing::new(vec![0u8; totp::SECRET_LEN]);
            getrandom::fill(secret.as_mut_slice()).map_err(|_| Failure::Internal)?;
            let b32 = Zeroizing::new(totp::base32(&secret));
            let sealed = seal::seal(seal_to, b32.as_bytes()).map_err(|_| Failure::Internal)?;
            let mut map = self.pending_totp.lock().map_err(|_| Failure::Internal)?;
            map.retain(|_, (_, at)| at.elapsed() < PENDING_TOTP_TTL);
            map.insert(user, (secret, Instant::now()));
            Ok(Response::Sealed(sealed))
        };
        run().unwrap_or_else(Response::Failed)
    }

    /// Active le code d'appli préparé, sur un premier code valide (preuve que l'appli est bien réglée).
    pub fn totp_confirm(
        &self,
        vault: &Vault,
        user: UserId,
        code: &str,
        seal_to: &[u8; 32],
    ) -> Response {
        let run = || -> Result<Response, Failure> {
            if self.totp_locked(&user)? {
                return Err(Failure::Locked);
            }
            let secret = {
                let map = self.pending_totp.lock().map_err(|_| Failure::Internal)?;
                match map.get(&user) {
                    Some((s, at)) if at.elapsed() < PENDING_TOTP_TTL => s.clone(),
                    _ => return Err(Failure::NotFound),
                }
            };
            let Some(step) = totp::verify(&secret, code, totp::now_step(), 0) else {
                self.totp_failed(&user)?;
                return Err(Failure::BadProof);
            };
            let first = !vault.has_factors(&user).map_err(|_| Failure::Internal)?;
            vault
                .set_totp(&user, &secret, step)
                .map_err(|_| Failure::Internal)?;
            self.pending_totp
                .lock()
                .map_err(|_| Failure::Internal)?
                .remove(&user);
            if !first {
                return Ok(Response::Ok);
            }
            // Premier facteur : codes de secours (appli perdue → nouveau réglage avec un code de secours).
            let (codes, hashes) = new_recovery_codes(&user)?;
            vault
                .set_recovery(&user, &hashes)
                .map_err(|_| Failure::Internal)?;
            seal::seal(seal_to, codes.as_bytes())
                .map(Response::Sealed)
                .map_err(|_| Failure::Internal)
        };
        run().unwrap_or_else(Response::Failed)
    }

    pub fn new_nonce(&self, user: UserId) -> Result<[u8; 32], Failure> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| Failure::Internal)?;
        let mut map = self.nonces.lock().map_err(|_| Failure::Internal)?;
        map.retain(|_, (_, at)| at.elapsed() < NONCE_TTL);
        map.insert(nonce, (user, Instant::now()));
        Ok(nonce)
    }

    /// Consomme le nonce (TOUJOURS, même si la preuve échoue ensuite : aucun second essai).
    fn take_nonce(&self, user: &UserId, nonce: &[u8; 32]) -> Result<bool, Failure> {
        let mut map = self.nonces.lock().map_err(|_| Failure::Internal)?;
        Ok(matches!(map.remove(nonce), Some((u, at)) if &u == user && at.elapsed() < NONCE_TTL))
    }

    /// Vérifie une preuve pour une action dont le défi se calcule à partir du nonce.
    fn check(
        &self,
        vault: &Vault,
        user: &UserId,
        proof: &Proof,
        challenge_of: impl Fn(&[u8; 32]) -> [u8; 32],
    ) -> Result<(), Failure> {
        match proof {
            Proof::None => Err(Failure::NeedProof),
            Proof::Recovery { code } => {
                match vault.consume_recovery(user, &recovery_hash(user, code)) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(Failure::BadProof),
                    Err(_) => Err(Failure::Internal),
                }
            }
            Proof::Totp { code } => self.check_totp(vault, user, code),
            Proof::Passkey { nonce, assertion } => {
                if !self.take_nonce(user, nonce)? {
                    return Err(Failure::BadProof);
                }
                let stored = vault.passkeys(user).map_err(|_| Failure::Internal)?;
                let pk = stored
                    .into_iter()
                    .find(|p| p.credential_id == assertion.credential_id)
                    .ok_or(Failure::BadProof)?;
                let key = webauthn::parse_cose(&pk.cose).map_err(|_| Failure::BadProof)?;
                let counter =
                    webauthn::verify(&self.rp, &key, pk.counter, assertion, &challenge_of(nonce))
                        .map_err(|_| Failure::BadProof)?;
                vault
                    .put_passkey(user, &StoredPasskey { counter, ..pk })
                    .map_err(|_| Failure::Internal)
            }
        }
    }

    /// Valide un retrait : PASSKEY (web, défi lié au wallet, à la destination et au montant) ou CODE
    /// D'APPLI (Telegram). Jamais un code de secours : il sert seulement à re-régler un facteur perdu.
    pub fn verify_withdraw(
        &self,
        vault: &Vault,
        user: &UserId,
        wallet: &[u8; 32],
        to: &[u8; 32],
        lamports: u64,
        proof: &Proof,
    ) -> Result<(), Failure> {
        match proof {
            Proof::Passkey { .. } => self.check(vault, user, proof, |n| {
                challenge::withdraw(user, wallet, to, lamports, n)
            }),
            Proof::Totp { code } => self.check_totp(vault, user, code),
            Proof::Recovery { .. } => Err(Failure::BadProof),
            Proof::None => Err(Failure::NeedProof),
        }
    }

    /// Valide la suppression d'un wallet : PASSKEY (défi lié à ce wallet) ou CODE D'APPLI. Jamais un code
    /// de secours.
    pub fn verify_delete_wallet(
        &self,
        vault: &Vault,
        user: &UserId,
        wallet: &[u8; 32],
        proof: &Proof,
    ) -> Result<(), Failure> {
        match proof {
            Proof::Passkey { .. } => self.check(vault, user, proof, |n| {
                challenge::delete_wallet(user, wallet, n)
            }),
            Proof::Totp { code } => self.check_totp(vault, user, code),
            Proof::Recovery { .. } => Err(Failure::BadProof),
            Proof::None => Err(Failure::NeedProof),
        }
    }

    pub fn register_passkey(
        &self,
        vault: &Vault,
        user: UserId,
        credential_id: Vec<u8>,
        cose: Vec<u8>,
        seal_to: &[u8; 32],
        proof: &Proof,
    ) -> Response {
        let run = || -> Result<Response, Failure> {
            // La clé doit être une clé de passkey valide AVANT toute autre chose.
            webauthn::parse_cose(&cose).map_err(|_| Failure::InvalidKey)?;
            let first = !vault.has_factors(&user).map_err(|_| Failure::Internal)?;
            if vault
                .passkeys(&user)
                .map_err(|_| Failure::Internal)?
                .iter()
                .any(|p| p.credential_id == credential_id)
            {
                return Err(Failure::AlreadyExists);
            }
            if !first {
                self.check(vault, &user, proof, |n| {
                    challenge::add_passkey(&user, &credential_id, &cose, n)
                })?;
            }
            vault
                .put_passkey(
                    &user,
                    &StoredPasskey {
                        credential_id: credential_id.clone(),
                        cose: cose.clone(),
                        counter: 0,
                    },
                )
                .map_err(|_| Failure::Internal)?;
            if !first {
                return Ok(Response::PasskeyRegistered {
                    recovery_sealed: None,
                });
            }
            // Premier facteur : le signer génère les codes de secours, scellés pour l'affichage unique.
            let (codes, hashes) = new_recovery_codes(&user)?;
            vault
                .set_recovery(&user, &hashes)
                .map_err(|_| Failure::Internal)?;
            let sealed = seal::seal(seal_to, codes.as_bytes()).map_err(|_| Failure::Internal)?;
            Ok(Response::PasskeyRegistered {
                recovery_sealed: Some(sealed),
            })
        };
        run().unwrap_or_else(Response::Failed)
    }

    pub fn verify_recovery(&self, vault: &Vault, user: UserId, code: &str) -> Response {
        match vault.consume_recovery(&user, &recovery_hash(&user, code)) {
            Ok(true) => Response::Ok,
            Ok(false) => Response::Failed(Failure::BadProof),
            Err(_) => Response::Failed(Failure::Internal),
        }
    }

    pub fn regenerate_recovery(
        &self,
        vault: &Vault,
        user: UserId,
        seal_to: &[u8; 32],
        proof: &Proof,
    ) -> Response {
        let run = || -> Result<Response, Failure> {
            self.check(vault, &user, proof, |n| {
                challenge::challenge(challenge::REGENERATE_RECOVERY, &user, &[], n)
            })?;
            let (codes, hashes) = new_recovery_codes(&user)?;
            vault
                .set_recovery(&user, &hashes)
                .map_err(|_| Failure::Internal)?;
            seal::seal(seal_to, codes.as_bytes())
                .map(Response::Sealed)
                .map_err(|_| Failure::Internal)
        };
        run().unwrap_or_else(Response::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::MasterKey;
    use crate::webauthn::testing::{Device, Tamper, rp};
    use x25519_dalek::{PublicKey, StaticSecret};

    const ALICE: UserId = [1; 16];
    const BOB: UserId = [2; 16];

    struct Env {
        _dir: tempfile::TempDir,
        vault: Vault,
        factors: Factors,
        api_key: StaticSecret,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let vault = Vault::open(&dir.path().join("v.redb"), MasterKey::from_bytes([7; 32]))
            .unwrap_or_else(|_| unreachable!());
        Env {
            _dir: dir,
            vault,
            factors: Factors::new(rp()),
            api_key: StaticSecret::from([3; 32]),
        }
    }

    impl Env {
        fn to(&self) -> [u8; 32] {
            PublicKey::from(&self.api_key).to_bytes()
        }
        fn register(&self, user: UserId, d: &Device, proof: Proof) -> Response {
            self.factors.register_passkey(
                &self.vault,
                user,
                d.credential_id.clone(),
                d.cose(),
                &self.to(),
                &proof,
            )
        }
        fn codes(&self, sealed: &[u8]) -> Vec<String> {
            let plain = seal::open(&self.api_key, sealed).unwrap_or_else(|_| unreachable!());
            String::from_utf8_lossy(&plain)
                .lines()
                .map(String::from)
                .collect()
        }
        /// Preuve « passkey existante » pour ajouter la passkey `new`.
        fn add_proof(
            &self,
            user: UserId,
            existing: &mut Device,
            new: &Device,
            t: &Tamper,
        ) -> Proof {
            let nonce = self
                .factors
                .new_nonce(user)
                .unwrap_or_else(|_| unreachable!());
            let c = challenge::add_passkey(&user, &new.credential_id, &new.cose(), &nonce);
            Proof::Passkey {
                nonce,
                assertion: existing.assert(&c, t),
            }
        }
    }

    fn first_codes(e: &Env, user: UserId, d: &Device) -> Vec<String> {
        match e.register(user, d, Proof::None) {
            Response::PasskeyRegistered {
                recovery_sealed: Some(s),
            } => e.codes(&s),
            other => panic!("premier enregistrement refusé : {other:?}"),
        }
    }

    #[test]
    fn premier_facteur_sans_preuve_avec_dix_codes_de_secours() {
        let e = env();
        let codes = first_codes(&e, ALICE, &Device::new(1));
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert!(
            codes
                .iter()
                .all(|c| c.len() == 11 && c.as_bytes()[5] == b'-')
        );
    }

    #[test]
    fn une_api_piratee_ne_peut_pas_ajouter_sa_passkey() {
        let e = env();
        first_codes(&e, ALICE, &Device::new(1));
        let mut attacker = Device::new(9);
        assert_eq!(
            e.register(ALICE, &attacker, Proof::None),
            Response::Failed(Failure::NeedProof)
        );
        // Le pirate signe avec SA clé : inconnue du registre.
        let p = e.add_proof(ALICE, &mut attacker, &Device::new(8), &Tamper::default());
        assert_eq!(
            e.register(ALICE, &Device::new(8), p),
            Response::Failed(Failure::BadProof)
        );
    }

    #[test]
    fn ajoute_une_passkey_avec_la_preuve_d_une_passkey_existante() {
        let e = env();
        let mut phone = Device::new(1);
        first_codes(&e, ALICE, &phone);
        let laptop = Device::new(2);
        let p = e.add_proof(ALICE, &mut phone, &laptop, &Tamper::default());
        assert_eq!(
            e.register(ALICE, &laptop, p),
            Response::PasskeyRegistered {
                recovery_sealed: None
            }
        );
        assert_eq!(e.vault.passkeys(&ALICE).map(|v| v.len()).unwrap_or(0), 2);
    }

    #[test]
    fn une_validation_ne_peut_pas_servir_pour_une_autre_cle_ni_etre_rejouee() {
        let e = env();
        let mut phone = Device::new(1);
        first_codes(&e, ALICE, &phone);
        let wanted = Device::new(2);
        let p = e.add_proof(ALICE, &mut phone, &wanted, &Tamper::default());
        // L'API piratée substitue SA clé à celle validée par l'utilisateur : défi différent.
        assert_eq!(
            e.register(ALICE, &Device::new(9), p.clone()),
            Response::Failed(Failure::BadProof)
        );
        // Rejouer la même validation : nonce déjà consommé.
        assert_eq!(
            e.register(ALICE, &wanted, p),
            Response::Failed(Failure::BadProof)
        );
    }

    fn withdraw_proof(e: &Env, user: UserId, d: &mut Device, to: [u8; 32], lamports: u64) -> Proof {
        let nonce = e.factors.new_nonce(user).unwrap_or_else(|_| unreachable!());
        let c = challenge::withdraw(&user, &[0xaa; 32], &to, lamports, &nonce);
        Proof::Passkey {
            nonce,
            assertion: d.assert(&c, &Tamper::default()),
        }
    }

    #[test]
    fn retrait_valide_par_passkey_et_rien_d_autre() {
        let e = env();
        let mut phone = Device::new(1);
        let codes = first_codes(&e, ALICE, &phone);
        let (w, to, sol) = ([0xaa; 32], [0xbb; 32], 1_000_000_000);
        let check = |p: &Proof, to: [u8; 32], amount: u64| {
            e.factors
                .verify_withdraw(&e.vault, &ALICE, &w, &to, amount, p)
        };
        // Validation correcte : acceptée une fois, puis plus jamais (nonce consommé).
        let p = withdraw_proof(&e, ALICE, &mut phone, to, sol);
        assert_eq!(check(&p, to, sol), Ok(()));
        assert_eq!(check(&p, to, sol), Err(Failure::BadProof));
        // API piratée : change le montant ou la destination après validation → défi différent.
        let p = withdraw_proof(&e, ALICE, &mut phone, to, sol);
        assert_eq!(check(&p, to, sol * 10), Err(Failure::BadProof));
        let p = withdraw_proof(&e, ALICE, &mut phone, to, sol);
        assert_eq!(check(&p, [0x66; 32], sol), Err(Failure::BadProof));
        // Code de secours ou aucune preuve : jamais pour un retrait.
        let code = Proof::Recovery {
            code: codes[0].clone(),
        };
        assert_eq!(check(&code, to, sol), Err(Failure::BadProof));
        assert_eq!(check(&Proof::None, to, sol), Err(Failure::NeedProof));
        // La passkey d'un autre compte : refusée.
        let mut bob_phone = Device::new(5);
        first_codes(&e, BOB, &bob_phone);
        let p = withdraw_proof(&e, ALICE, &mut bob_phone, to, sol);
        assert_eq!(check(&p, to, sol), Err(Failure::BadProof));
    }

    /// Code actuel du code d'appli préparé (comme l'appli du téléphone).
    fn pending_code(e: &Env, user: UserId) -> String {
        let map = e
            .factors
            .pending_totp
            .lock()
            .unwrap_or_else(|_| unreachable!());
        let (secret, _) = map
            .get(&user)
            .unwrap_or_else(|| panic!("aucun code préparé"));
        format!("{:06}", totp::code_at(secret, totp::now_step()))
    }

    /// Code actuel du code d'appli ACTIF, au pas suivant le dernier utilisé (codes successifs distincts).
    fn next_code(e: &Env, user: UserId) -> String {
        let t = e
            .vault
            .totp(&user)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("pas de code d'appli"));
        let step = (t.last_step + 1).max(totp::now_step() - 1);
        format!("{:06}", totp::code_at(&t.secret, step))
    }

    fn setup(e: &Env, user: UserId, proof: Proof) -> Response {
        e.factors.totp_setup(&e.vault, user, &e.to(), &proof)
    }

    #[test]
    fn telegram_seul_code_d_appli_comme_premier_facteur_avec_codes_de_secours() {
        let e = env();
        let sealed = match setup(&e, ALICE, Proof::None) {
            Response::Sealed(s) => s,
            other => panic!("réglage refusé : {other:?}"),
        };
        // Le secret affiché (base32) est bien celui préparé dans le signer.
        let b32 = String::from_utf8(
            seal::open(&e.api_key, &sealed)
                .map(|z| z.to_vec())
                .unwrap_or_default(),
        )
        .unwrap_or_default();
        assert_eq!(b32.len(), 32);
        // Un code faux n'active rien.
        assert_eq!(
            e.factors.totp_confirm(&e.vault, ALICE, "000000", &e.to()),
            if pending_code(&e, ALICE) == "000000" {
                Response::Ok
            } else {
                Response::Failed(Failure::BadProof)
            }
        );
        let code = pending_code(&e, ALICE);
        match e.factors.totp_confirm(&e.vault, ALICE, &code, &e.to()) {
            Response::Sealed(s) => assert_eq!(e.codes(&s).len(), RECOVERY_CODES),
            other => panic!("activation refusée : {other:?}"),
        }
        assert!(e.vault.totp(&ALICE).ok().flatten().is_some());
    }

    #[test]
    fn un_voleur_de_session_telegram_ne_peut_pas_installer_son_appli() {
        let e = env();
        // Compte déjà protégé (passkey) : réglage sans preuve refusé.
        first_codes(&e, ALICE, &Device::new(1));
        assert_eq!(
            setup(&e, ALICE, Proof::None),
            Response::Failed(Failure::NeedProof)
        );
        assert_eq!(
            setup(
                &e,
                ALICE,
                Proof::Totp {
                    code: "123456".into()
                }
            ),
            Response::Failed(Failure::BadProof)
        );
        // Compte Telegram avec code d'appli : remplacer l'appli exige un code valide (ou un code de secours).
        let e = env();
        setup(&e, BOB, Proof::None);
        let codes = match e
            .factors
            .totp_confirm(&e.vault, BOB, &pending_code(&e, BOB), &e.to())
        {
            Response::Sealed(s) => e.codes(&s),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            setup(&e, BOB, Proof::None),
            Response::Failed(Failure::NeedProof)
        );
        assert!(matches!(
            setup(
                &e,
                BOB,
                Proof::Recovery {
                    code: codes[0].clone()
                }
            ),
            Response::Sealed(_)
        ));
    }

    #[test]
    fn retrait_par_code_d_appli_usage_unique_et_anti_force_brute() {
        let e = env();
        setup(&e, ALICE, Proof::None);
        e.factors
            .totp_confirm(&e.vault, ALICE, &pending_code(&e, ALICE), &e.to());
        let w = |code: &str| {
            e.factors.verify_withdraw(
                &e.vault,
                &ALICE,
                &[0xaa; 32],
                &[0xbb; 32],
                1_000,
                &Proof::Totp { code: code.into() },
            )
        };
        let code = next_code(&e, ALICE);
        assert_eq!(w(&code), Ok(()));
        // Le même code rejoué : refusé.
        assert_eq!(w(&code), Err(Failure::BadProof));
        // Force brute : après 5 erreurs, bloqué, même avec le BON code.
        let e2 = env();
        setup(&e2, BOB, Proof::None);
        e2.factors
            .totp_confirm(&e2.vault, BOB, &pending_code(&e2, BOB), &e2.to());
        let w2 = |code: &str| {
            e2.factors.verify_withdraw(
                &e2.vault,
                &BOB,
                &[0xaa; 32],
                &[0xbb; 32],
                1_000,
                &Proof::Totp { code: code.into() },
            )
        };
        let good = next_code(&e2, BOB);
        let bad = if good == "111111" { "222222" } else { "111111" };
        for _ in 0..5 {
            assert_eq!(w2(bad), Err(Failure::BadProof));
        }
        assert_eq!(w2(&good), Err(Failure::Locked));
        // Les erreurs de Bob ne bloquent pas Alice.
        assert_eq!(e2.factors.totp_locked(&ALICE), Ok(false));
    }

    #[test]
    fn un_nonce_d_un_autre_compte_ou_expire_ne_marche_pas() {
        let e = env();
        let mut phone = Device::new(1);
        first_codes(&e, ALICE, &phone);
        let new = Device::new(2);
        let nonce = e.factors.new_nonce(BOB).unwrap_or_else(|_| unreachable!());
        let c = challenge::add_passkey(&ALICE, &new.credential_id, &new.cose(), &nonce);
        let p = Proof::Passkey {
            nonce,
            assertion: phone.assert(&c, &Tamper::default()),
        };
        assert_eq!(
            e.register(ALICE, &new, p),
            Response::Failed(Failure::BadProof)
        );
    }

    #[test]
    fn passkeys_perdues_un_code_de_secours_permet_d_en_ajouter_une() {
        let e = env();
        let codes = first_codes(&e, ALICE, &Device::new(1));
        let new_phone = Device::new(3);
        let p = Proof::Recovery {
            code: codes[0].to_lowercase(),
        };
        assert_eq!(
            e.register(ALICE, &new_phone, p.clone()),
            Response::PasskeyRegistered {
                recovery_sealed: None
            }
        );
        // Le code a servi : il ne marche plus.
        assert_eq!(
            e.register(ALICE, &Device::new(4), p),
            Response::Failed(Failure::BadProof)
        );
    }

    #[test]
    fn les_codes_d_un_compte_ne_servent_pas_sur_un_autre() {
        let e = env();
        let codes = first_codes(&e, ALICE, &Device::new(1));
        first_codes(&e, BOB, &Device::new(2));
        assert_eq!(
            e.factors.verify_recovery(&e.vault, BOB, &codes[0]),
            Response::Failed(Failure::BadProof)
        );
        assert_eq!(
            e.factors.verify_recovery(&e.vault, ALICE, &codes[0]),
            Response::Ok
        );
        assert_eq!(
            e.factors.verify_recovery(&e.vault, ALICE, &codes[0]),
            Response::Failed(Failure::BadProof)
        );
    }

    #[test]
    fn regenerer_les_codes_exige_une_preuve_et_invalide_les_anciens() {
        let e = env();
        let mut phone = Device::new(1);
        let old = first_codes(&e, ALICE, &phone);
        assert_eq!(
            e.factors
                .regenerate_recovery(&e.vault, ALICE, &e.to(), &Proof::None),
            Response::Failed(Failure::NeedProof)
        );
        let nonce = e
            .factors
            .new_nonce(ALICE)
            .unwrap_or_else(|_| unreachable!());
        let c = challenge::challenge(challenge::REGENERATE_RECOVERY, &ALICE, &[], &nonce);
        let p = Proof::Passkey {
            nonce,
            assertion: phone.assert(&c, &Tamper::default()),
        };
        let Response::Sealed(s) = e.factors.regenerate_recovery(&e.vault, ALICE, &e.to(), &p)
        else {
            panic!("régénération refusée")
        };
        let fresh = e.codes(&s);
        assert_eq!(
            e.factors.verify_recovery(&e.vault, ALICE, &old[1]),
            Response::Failed(Failure::BadProof)
        );
        assert_eq!(
            e.factors.verify_recovery(&e.vault, ALICE, &fresh[0]),
            Response::Ok
        );
    }

    #[test]
    fn refuse_une_cle_de_passkey_invalide_et_les_doublons() {
        let e = env();
        let d = Device::new(1);
        let r = e.factors.register_passkey(
            &e.vault,
            ALICE,
            vec![1],
            b"pas une cle".to_vec(),
            &e.to(),
            &Proof::None,
        );
        assert_eq!(r, Response::Failed(Failure::InvalidKey));
        first_codes(&e, ALICE, &d);
        let codes = e.vault.passkeys(&ALICE).map(|v| v.len()).unwrap_or(0);
        assert_eq!(
            e.register(ALICE, &d, Proof::None),
            Response::Failed(Failure::AlreadyExists)
        );
        assert_eq!(
            e.vault.passkeys(&ALICE).map(|v| v.len()).unwrap_or(0),
            codes
        );
    }
}
