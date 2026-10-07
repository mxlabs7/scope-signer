//! Défis des actions sensibles (ajout d'une passkey, régénération des codes, retraits…).
//!
//! La passkey de l'utilisateur signe ce défi ; le signer le RECALCULE à partir de l'action demandée
//! et d'un nonce à usage unique qu'il a lui-même émis. Une API piratée ne peut donc ni changer
//! l'action (montant, adresse, nouvelle clé…), ni rejouer une ancienne validation.
//!
//! Défi = SHA-256( "scope-v1" 0 ‖ but 0 ‖ utilisateur (16) ‖ pour chaque paramètre : longueur (u32 BE) ‖ octets ‖ nonce (32) ).
//! Même calcul côté API (TypeScript), avec un vecteur de test commun.

use sha2::{Digest, Sha256};

pub const ADD_PASSKEY: &str = "add-passkey";
pub const REGENERATE_RECOVERY: &str = "regenerate-recovery";
pub const WITHDRAW: &str = "withdraw";
pub const ADD_TOTP: &str = "add-totp";
pub const DELETE_WALLET: &str = "delete-wallet";

pub fn challenge(purpose: &str, user: &[u8; 16], params: &[&[u8]], nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"scope-v1\0");
    h.update(purpose.as_bytes());
    h.update([0]);
    h.update(user);
    for p in params {
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    h.update(nonce);
    h.finalize().into()
}

/// Défi de l'ajout d'une passkey : lié à la passkey AJOUTÉE (son id et sa clé publique).
pub fn add_passkey(
    user: &[u8; 16],
    credential_id: &[u8],
    cose: &[u8],
    nonce: &[u8; 32],
) -> [u8; 32] {
    challenge(ADD_PASSKEY, user, &[credential_id, cose], nonce)
}

/// Défi d'un retrait de SOL : lié au wallet source, à l'adresse de destination et au montant EXACT.
pub fn withdraw(
    user: &[u8; 16],
    wallet: &[u8; 32],
    to: &[u8; 32],
    lamports: u64,
    nonce: &[u8; 32],
) -> [u8; 32] {
    challenge(
        WITHDRAW,
        user,
        &[wallet, to, &lamports.to_be_bytes()],
        nonce,
    )
}

/// Défi de la suppression d'un wallet : lié à CE wallet.
pub fn delete_wallet(user: &[u8; 16], wallet: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    challenge(DELETE_WALLET, user, &[wallet], nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn change_des_que_l_action_change() {
        let base = add_passkey(&[1; 16], b"cred", b"cle", &[2; 32]);
        assert_ne!(
            base,
            add_passkey(&[1; 16], b"cred", b"cle-pirate", &[2; 32])
        );
        assert_ne!(base, add_passkey(&[9; 16], b"cred", b"cle", &[2; 32]));
        assert_ne!(base, add_passkey(&[1; 16], b"cred", b"cle", &[3; 32]));
        // Les paramètres sont délimités : « ab » + « c » ≠ « a » + « bc ».
        assert_ne!(
            challenge("x", &[0; 16], &[b"ab", b"c"], &[0; 32]),
            challenge("x", &[0; 16], &[b"a", b"bc"], &[0; 32])
        );
    }

    /// Vecteur commun avec packages/protocol (TypeScript).
    #[test]
    fn vecteur_commun_avec_typescript() {
        assert_eq!(
            hex(&add_passkey(
                &[0x11; 16],
                b"cred-id",
                b"cose-key",
                &[0x22; 32]
            )),
            VECTOR
        );
    }

    /// Vecteur commun avec packages/protocol (TypeScript) pour les retraits.
    #[test]
    fn vecteur_retrait_commun_avec_typescript() {
        let base = withdraw(
            &[0x11; 16],
            &[0x33; 32],
            &[0x44; 32],
            1_500_000_000,
            &[0x22; 32],
        );
        assert_eq!(hex(&base), WITHDRAW_VECTOR);
        assert_ne!(
            base,
            withdraw(
                &[0x11; 16],
                &[0x33; 32],
                &[0x44; 32],
                1_500_000_001,
                &[0x22; 32]
            )
        );
        assert_ne!(
            base,
            withdraw(
                &[0x11; 16],
                &[0x33; 32],
                &[0x45; 32],
                1_500_000_000,
                &[0x22; 32]
            )
        );
        assert_ne!(
            base,
            withdraw(
                &[0x11; 16],
                &[0x34; 32],
                &[0x44; 32],
                1_500_000_000,
                &[0x22; 32]
            )
        );
    }

    const WITHDRAW_VECTOR: &str =
        "4e339a88ebed517f0dfaa482087ea6811a109ac33ed73cc2e91383113c09e6da";

    const VECTOR: &str = "d7f687b027e8416b7bd37dc73c0917d9787c21203d23a4d059bb4f53008dadc5";
}
