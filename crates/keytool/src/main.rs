//! Cérémonie de la clé maître du signer.
//!
//! `scope-keytool new` : génère une clé maître et la découpe en N morceaux (Shamir), dont K suffisent.
//! `scope-keytool recover <morceau> <morceau>…` : reconstruit la clé maître.
//!
//! Format d'un morceau : `scope1-<empreinte>-<morceau>-<contrôle>` (hexadécimal).
//! - l'empreinte (4 octets) identifie la clé : mélanger des morceaux de deux cérémonies est détecté ;
//! - le contrôle (4 octets) détecte une faute de frappe dans le morceau.

use anyhow::{Context, Result, bail, ensure};
use blahaj::{Share, Sharks};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const PREFIX: &str = "scope1";

/// 4 premiers octets du SHA-256, en hexadécimal (empreinte de la clé, contrôle des morceaux).
fn tag(data: &[u8]) -> String {
    hex(&Sha256::digest(data)[..4])
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    ensure!(s.len().is_multiple_of(2), "hexadécimal de longueur impaire");
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(s.get(i..i + 2).context("hex")?, 16)
                .context("caractère non hexadécimal")
        })
        .collect()
}

/// Découpe la clé en `n` morceaux, dont `k` suffisent.
pub fn split(key: &[u8; 32], k: u8, n: u8) -> Result<Vec<String>> {
    ensure!(k >= 2 && n >= k, "il faut 2 ≤ seuil ≤ nombre de morceaux");
    let fp = tag(key);
    let shares: Vec<Share> = Sharks(k).dealer(key).take(n as usize).collect();
    Ok(shares
        .iter()
        .map(|s| {
            let bytes = Vec::from(s);
            format!("{PREFIX}-{fp}-{}-{}", hex(&bytes), tag(&bytes))
        })
        .collect())
}

/// Reconstruit la clé à partir d'au moins `k` morceaux.
pub fn recover(parts: &[String], k: u8) -> Result<Zeroizing<[u8; 32]>> {
    let mut fingerprint = None;
    let mut shares = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        let fields: Vec<&str> = p.trim().split('-').collect();
        let [prefix, fp, body, check] = fields.as_slice() else {
            bail!("morceau n°{} mal formé", i + 1);
        };
        ensure!(*prefix == PREFIX, "morceau n°{} : préfixe inconnu", i + 1);
        let bytes = unhex(body)?;
        ensure!(
            tag(&bytes) == *check,
            "morceau n°{} : faute de frappe détectée",
            i + 1
        );
        match fingerprint {
            None => fingerprint = Some(fp.to_string()),
            Some(ref f) => ensure!(
                f == fp,
                "morceau n°{} : il vient d'une AUTRE clé maître",
                i + 1
            ),
        }
        shares.push(
            Share::try_from(bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("morceau n°{} : {e}", i + 1))?,
        );
    }
    ensure!(shares.len() >= k as usize, "il faut au moins {k} morceaux");
    let secret = Zeroizing::new(
        Sharks(k)
            .recover(&shares)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    );
    let key: [u8; 32] = secret
        .as_slice()
        .try_into()
        .context("clé reconstruite invalide")?;
    ensure!(
        Some(tag(&key)) == fingerprint,
        "la clé reconstruite ne correspond pas à son empreinte"
    );
    Ok(Zeroizing::new(key))
}

fn rules_key(path: &str) -> Result<ed25519_dalek::SigningKey> {
    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    let bytes = Zeroizing::new(unhex(text.trim())?);
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("la clé doit faire 32 octets")?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("new") => {
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::fill(key.as_mut())
                .map_err(|e| anyhow::anyhow!("aléa indisponible : {e}"))?;
            println!(
                "CLÉ MAÎTRE (à charger dans le coffre à secrets, jamais ailleurs) :\n{}\n",
                hex(key.as_slice())
            );
            println!(
                "MORCEAUX (2 sur 3 suffisent) — à ranger à 3 endroits différents, hors ligne :"
            );
            for (i, s) in split(&key, 2, 3)?.iter().enumerate() {
                println!("  {} : {s}", i + 1);
            }
            Ok(())
        }
        // Développement local uniquement : écrit une clé maître dans un fichier (droits 600).
        Some("new-dev") => {
            use std::os::unix::fs::OpenOptionsExt;
            let path = args
                .get(1)
                .context("usage : scope-keytool new-dev <fichier>")?;
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::fill(key.as_mut())
                .map_err(|e| anyhow::anyhow!("aléa indisponible : {e}"))?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            std::io::Write::write_all(&mut f, hex(key.as_slice()).as_bytes())?;
            eprintln!(
                "clé maître de DÉVELOPPEMENT écrite dans {path} (jamais pour de vrais fonds)"
            );
            Ok(())
        }
        // Découpe une clé maître EXISTANTE (fichier hex) : un morceau par ligne.
        Some("split") => {
            let path = args
                .get(1)
                .context("usage : scope-keytool split <fichier>")?;
            let text = Zeroizing::new(std::fs::read_to_string(path)?);
            let bytes = Zeroizing::new(unhex(text.trim())?);
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .context("la clé doit faire 32 octets")?;
            for s in split(&key, 2, 3)? {
                println!("{s}");
            }
            Ok(())
        }
        // Clé d'autorité des règles (DEV / STAGING uniquement : en production, clé gardée hors ligne).
        Some("rules-key") => {
            use std::os::unix::fs::OpenOptionsExt;
            let path = args
                .get(1)
                .context("usage : scope-keytool rules-key <fichier>")?;
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(seed.as_mut())
                .map_err(|e| anyhow::anyhow!("aléa indisponible : {e}"))?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            std::io::Write::write_all(&mut f, hex(seed.as_slice()).as_bytes())?;
            println!(
                "{}",
                hex(ed25519_dalek::SigningKey::from_bytes(&seed)
                    .verifying_key()
                    .as_bytes())
            );
            Ok(())
        }
        Some("rules-pubkey") => {
            let path = args
                .get(1)
                .context("usage : scope-keytool rules-pubkey <fichier>")?;
            println!("{}", hex(rules_key(path)?.verifying_key().as_bytes()));
            Ok(())
        }
        Some("rules-sign") => {
            use ed25519_dalek::Signer as _;
            let (Some(rules), Some(key)) = (args.get(1), args.get(2)) else {
                bail!("usage : scope-keytool rules-sign <rules.json> <clé d'autorité>");
            };
            let json = std::fs::read(rules)?;
            let sig = rules_key(key)?.sign(&json);
            std::fs::write(format!("{rules}.sig"), hex(&sig.to_bytes()))?;
            eprintln!("{rules}.sig écrit");
            Ok(())
        }
        Some("recover") => {
            let key = recover(&args[1..], 2)?;
            println!("{}", hex(key.as_slice()));
            Ok(())
        }
        _ => bail!(
            "usage : scope-keytool new | new-dev <fichier> | split <fichier> | recover <morceau> <morceau>"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        std::array::from_fn(|i| i as u8 * 7)
    }

    #[test]
    fn deux_morceaux_quelconques_sur_trois_suffisent() -> Result<()> {
        let parts = split(&key(), 2, 3)?;
        for pair in [[0, 1], [0, 2], [1, 2], [2, 0]] {
            let chosen: Vec<String> = pair.iter().map(|&i| parts[i].clone()).collect();
            assert_eq!(*recover(&chosen, 2)?, key());
        }
        Ok(())
    }

    #[test]
    fn un_seul_morceau_ne_suffit_pas() -> Result<()> {
        let parts = split(&key(), 2, 3)?;
        assert!(recover(&parts[..1], 2).is_err());
        Ok(())
    }

    #[test]
    fn detecte_une_faute_de_frappe() -> Result<()> {
        let mut parts = split(&key(), 2, 3)?;
        let p = &mut parts[0];
        let pos = p.len() - 12;
        let c = if &p[pos..pos + 1] == "a" { "b" } else { "a" };
        p.replace_range(pos..pos + 1, c);
        assert!(recover(&parts[..2], 2).is_err());
        Ok(())
    }

    #[test]
    fn detecte_des_morceaux_de_deux_cles_differentes() -> Result<()> {
        let a = split(&key(), 2, 3)?;
        let b = split(&[42; 32], 2, 3)?;
        assert!(recover(&[a[0].clone(), b[1].clone()], 2).is_err());
        Ok(())
    }

    #[test]
    fn deux_ceremonies_donnent_des_morceaux_differents() -> Result<()> {
        assert_ne!(split(&key(), 2, 3)?, split(&key(), 2, 3)?);
        Ok(())
    }
}
