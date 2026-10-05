//! Scellement : chiffrement de bout en bout d'un secret pour le détenteur d'une clé X25519.
//!
//! Les clés privées des wallets ne transitent JAMAIS en clair par Redis (qui écrit sur disque) :
//! - création : le signer scelle la clé pour une clé éphémère de l'API, détruite après affichage ;
//! - import   : l'API scelle la clé pour la clé de transport du signer.
//!
//! Format : `[32 : clé publique éphémère][12 : nonce][chiffré + tag]`.
//! Clé symétrique = HKDF-SHA256(secret X25519, sel = éphémère ‖ destinataire, info = "scope-seal-v1").
//! Le même format est implémenté côté API (TypeScript), avec des vecteurs de test communs.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const INFO: &[u8] = b"scope-seal-v1";
const EPH: usize = 32;
const NONCE: usize = 12;

#[derive(Debug, PartialEq, Eq)]
pub struct SealError;

fn symmetric_key(
    shared: &[u8; 32],
    eph_pub: &[u8; 32],
    to: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let salt = [eph_pub.as_slice(), to.as_slice()].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(INFO, key.as_mut())
        .map_err(|_| SealError)?;
    Ok(key)
}

/// Scelle avec une clé éphémère et un nonce donnés (vecteurs de test). En production : `seal`.
pub fn seal_with(
    eph: [u8; 32],
    nonce: [u8; NONCE],
    to: &[u8; 32],
    plain: &[u8],
) -> Result<Vec<u8>, SealError> {
    let eph = StaticSecret::from(eph);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*to));
    if !shared.was_contributory() {
        return Err(SealError); // clé destinataire invalide (point de faible ordre)
    }
    let key = symmetric_key(shared.as_bytes(), &eph_pub, to)?;
    let ct = ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plain,
                aad: INFO,
            },
        )
        .map_err(|_| SealError)?;
    Ok([eph_pub.as_slice(), &nonce, &ct].concat())
}

/// Scelle `plain` pour le détenteur de la clé publique X25519 `to`.
pub fn seal(to: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut eph = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; NONCE];
    getrandom::fill(eph.as_mut()).map_err(|_| SealError)?;
    getrandom::fill(&mut nonce).map_err(|_| SealError)?;
    seal_with(*eph, nonce, to, plain)
}

/// Ouvre un scellé destiné à `secret`.
pub fn open(secret: &StaticSecret, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
    if sealed.len() <= EPH + NONCE {
        return Err(SealError);
    }
    let eph_pub: [u8; 32] = sealed[..EPH].try_into().map_err(|_| SealError)?;
    let nonce: [u8; NONCE] = sealed[EPH..EPH + NONCE].try_into().map_err(|_| SealError)?;
    let shared = secret.diffie_hellman(&PublicKey::from(eph_pub));
    if !shared.was_contributory() {
        return Err(SealError);
    }
    let to = PublicKey::from(secret).to_bytes();
    let key = symmetric_key(shared.as_bytes(), &eph_pub, &to)?;
    ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &sealed[EPH + NONCE..],
                aad: INFO,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SealError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn aller_retour() -> Result<(), SealError> {
        let me = StaticSecret::from([5; 32]);
        let to = PublicKey::from(&me).to_bytes();
        let sealed = seal(&to, b"cle privee")?;
        assert_eq!(open(&me, &sealed)?.as_slice(), b"cle privee");
        Ok(())
    }

    #[test]
    fn un_autre_destinataire_ne_peut_pas_ouvrir() -> Result<(), SealError> {
        let me = StaticSecret::from([5; 32]);
        let sealed = seal(&PublicKey::from(&me).to_bytes(), b"secret")?;
        assert_eq!(open(&StaticSecret::from([6; 32]), &sealed), Err(SealError));
        Ok(())
    }

    #[test]
    fn un_scelle_modifie_est_refuse() -> Result<(), SealError> {
        let me = StaticSecret::from([5; 32]);
        let mut sealed = seal(&PublicKey::from(&me).to_bytes(), b"secret")?;
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert_eq!(open(&me, &sealed), Err(SealError));
        assert_eq!(open(&me, &sealed[..20]), Err(SealError));
        Ok(())
    }

    #[test]
    fn refuse_une_cle_destinataire_de_faible_ordre() {
        assert_eq!(seal(&[0; 32], b"x"), Err(SealError));
    }

    /// Vecteur de test partagé avec l'implémentation TypeScript (apps/api/test/seal.test.ts).
    #[test]
    fn vecteur_commun_avec_typescript() -> Result<(), SealError> {
        let recipient = StaticSecret::from([0x11; 32]);
        let to = PublicKey::from(&recipient).to_bytes();
        let sealed = seal_with([0x22; 32], [0x33; 12], &to, b"scope")?;
        assert_eq!(hex(&to), VECTOR_TO);
        assert_eq!(hex(&sealed), VECTOR_SEALED);
        Ok(())
    }

    const VECTOR_TO: &str = "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13";
    const VECTOR_SEALED: &str = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f203333333333333333333333335a7d0e391f5f26119ce6db83839d43c74204143d3c";
}
