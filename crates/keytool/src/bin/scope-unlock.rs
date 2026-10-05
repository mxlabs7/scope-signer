//! Livre la clé maître au signer verrouillé, par son socket d'amorçage.
//!
//! Usage : `scope-unlock <socket d'amorçage> <source de la clé maître> [--watch]`
//! - source = un fichier (clé en hexadécimal, 64 caractères) : dev et staging ;
//! - source = une adresse `https://…` : PRODUCTION. La clé vient d'un coffre externe qui ne répond qu'à
//!   l'IP du serveur et au jeton `UNLOCK_TOKEN` (variable d'environnement). Elle n'est jamais écrite sur
//!   disque : lue à chaque livraison, gardée en mémoire le temps de la transmettre, puis effacée.
//! - `--watch` : reste actif et redéverrouille le signer à chaque redémarrage (nouvelle lecture du coffre,
//!   donc nouvelle alerte côté coffre).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use zeroize::Zeroizing;

fn parse_hex(text: &str) -> Result<Zeroizing<[u8; 32]>> {
    let hex = text.trim();
    ensure!(
        hex.len() == 64,
        "la clé maître doit faire 64 caractères hexadécimaux"
    );
    let mut key = Zeroizing::new([0u8; 32]);
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2).context("hex")?, 16)
            .context("hex invalide")?;
    }
    Ok(key)
}

/// Clé lue dans le coffre externe (HTTPS, jeton), sans jamais passer par le disque.
fn fetch_key(url: &str) -> Result<Zeroizing<[u8; 32]>> {
    let token = Zeroizing::new(std::env::var("UNLOCK_TOKEN").context("UNLOCK_TOKEN manquant")?);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut res = agent
        .get(url)
        .header("authorization", &format!("Bearer {}", token.as_str()))
        .call()
        .context("coffre externe injoignable")?;
    let status = res.status().as_u16();
    let body = Zeroizing::new(
        res.body_mut()
            .read_to_string()
            .context("réponse du coffre illisible")?,
    );
    ensure!(
        status == 200,
        "le coffre externe a REFUSÉ la demande (HTTP {status})"
    );
    parse_hex(&body)
}

fn read_key(source: &str) -> Result<Zeroizing<[u8; 32]>> {
    if source.starts_with("https://") {
        return fetch_key(source);
    }
    let path = Path::new(source);
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .with_context(|| format!("clé illisible : {}", path.display()))?,
    );
    parse_hex(&text)
}

/// Une tentative de livraison. `Ok(false)` si le signer n'attend pas de clé (déjà déverrouillé ou pas démarré).
fn deliver(socket: &Path, source: &str) -> Result<bool> {
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return Ok(false);
    };
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    let key = read_key(source)?;
    stream.write_all(key.as_slice())?;
    let mut status = [0u8; 1];
    stream.read_exact(&mut status)?;
    match status[0] {
        0 => Ok(true),
        _ => bail!("le signer a REFUSÉ la clé maître (mauvaise clé pour ce coffre)"),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(socket), Some(source)) = (args.first(), args.get(1)) else {
        bail!("usage : scope-unlock <socket d'amorçage> <fichier ou https://coffre> [--watch]");
    };
    let socket = Path::new(socket);
    let watch = args.iter().any(|a| a == "--watch");

    loop {
        match deliver(socket, source) {
            Ok(true) => {
                println!("signer déverrouillé");
                if !watch {
                    return Ok(());
                }
            }
            Ok(false) => {}
            // Une clé ou une demande refusée est grave : on s'arrête et on le signale, sans réessayer en boucle.
            Err(e) => return Err(e),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cle_hexadecimale() {
        let k = parse_hex(&format!("{}\n", "ab".repeat(32))).expect("clé valide");
        assert_eq!(k[0], 0xab);
        assert!(parse_hex("abcd").is_err());
        assert!(parse_hex(&"zz".repeat(32)).is_err());
    }
}
