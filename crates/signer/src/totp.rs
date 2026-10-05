//! Codes d'appli (TOTP, RFC 6238 : HMAC-SHA1, pas de 30 s, 6 chiffres), vérifiés PAR LE SIGNER.
//! Le secret n'existe que chiffré dans le coffre du signer : ni l'API ni le bot ne le gardent.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

pub const STEP_SECONDS: u64 = 30;
pub const SECRET_LEN: usize = 20;

/// Code à 6 chiffres pour un pas de temps donné.
pub fn code_at(secret: &[u8], step: u64) -> u32 {
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(secret) else {
        return u32::MAX; // jamais un code valide
    };
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = usize::from(h[19] & 0x0f);
    let bin = (u32::from(h[off] & 0x7f) << 24)
        | (u32::from(h[off + 1]) << 16)
        | (u32::from(h[off + 2]) << 8)
        | u32::from(h[off + 3]);
    bin % 1_000_000
}

pub fn now_step() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / STEP_SECONDS)
        .unwrap_or(0)
}

/// Vérifie `code` (tolérance d'un pas avant/après pour le décalage d'horloge). Renvoie le pas reconnu,
/// seulement s'il est POSTÉRIEUR au dernier pas utilisé (un code ne sert qu'une fois).
pub fn verify(secret: &[u8], code: &str, now: u64, last_used: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u32 = code.parse().ok()?;
    [now.saturating_sub(1), now, now + 1]
        .into_iter()
        .find(|&s| s > last_used && code_at(secret, s) == value)
}

/// Secret en base32 (format des applis : Google Authenticator, Authy…).
pub fn base32(secret: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in secret {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(A[((buf >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(A[((buf << (5 - bits)) & 31) as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    /// Vecteurs officiels de la RFC 6238 (SHA-1), tronqués à 6 chiffres.
    #[test]
    fn vecteurs_de_la_rfc_6238() {
        for (t, code) in [
            (59u64, 287_082u32),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
        ] {
            assert_eq!(code_at(RFC_SECRET, t / STEP_SECONDS), code, "t = {t}");
        }
    }

    #[test]
    fn un_code_ne_sert_qu_une_fois_et_expire() {
        let now = 1_000;
        let code = format!("{:06}", code_at(RFC_SECRET, now));
        let used = verify(RFC_SECRET, &code, now, 0);
        assert_eq!(used, Some(now));
        // Rejoué : refusé (pas déjà utilisé).
        assert_eq!(verify(RFC_SECRET, &code, now, now), None);
        // Trop vieux (plus de 30 s de décalage) : refusé.
        assert_eq!(verify(RFC_SECRET, &code, now + 2, 0), None);
        // Format invalide.
        for bad in ["", "12345", "1234567", "12a456", " "] {
            assert_eq!(verify(RFC_SECRET, bad, now, 0), None);
        }
    }

    #[test]
    fn base32_standard() {
        assert_eq!(
            base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }
}
