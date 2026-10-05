//! Signer Scope : seul composant qui touche aux clés.
//! Aucun accès réseau, aucune fonction d'export. Deux points d'entrée locaux (sockets Unix) :
//! - le socket d'AMORÇAGE, réservé au programme `scope-unlock`, qui livre la clé maître au démarrage ;
//! - le socket principal, réservé à l'utilisateur système du moteur.
//!
//! Démarrage : le signer est VERROUILLÉ tant qu'il n'a pas reçu une clé maître valide.

mod budget;
mod factors;
mod rules;
mod seal;
mod totp;
#[allow(dead_code)] // wallets_of : utilisé plus tard (liste côté signer)
mod vault;
mod webauthn;
mod withdraw;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::{Signer as _, SigningKey};
use scope_protocol::signer_frame::{Failure, Request, Response, body_len, frame};
use scope_solana as solana;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};
use vault::{MasterKey, Vault, VaultError};
use zeroize::Zeroizing;

struct Config {
    socket: PathBuf,
    /// UID système autorisé à parler au signer (celui du moteur).
    allowed_uid: u32,
    boot_socket: PathBuf,
    /// UID système autorisé à livrer la clé maître (celui de `scope-unlock`).
    boot_uid: u32,
    vault: PathBuf,
    /// Site et origines des passkeys : configurés DANS le signer, jamais fournis par l'API.
    rp: webauthn::RelyingParty,
    /// Fichier de règles (sa signature est dans `<fichier>.sig`).
    rules: PathBuf,
    /// Clé publique de l'autorité qui signe les règles (gardée hors ligne en production), en hex.
    rules_authority: ed25519_dalek::VerifyingKey,
}

fn env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} manquant"))
}

impl Config {
    fn from_env() -> Result<Self> {
        Ok(Self {
            socket: env("SIGNER_SOCKET")?.into(),
            allowed_uid: env("SIGNER_ALLOWED_UID")?
                .parse()
                .context("SIGNER_ALLOWED_UID invalide")?,
            boot_socket: env("SIGNER_BOOT_SOCKET")?.into(),
            boot_uid: env("SIGNER_BOOT_UID")?
                .parse()
                .context("SIGNER_BOOT_UID invalide")?,
            vault: env("SIGNER_VAULT")?.into(),
            rp: webauthn::RelyingParty {
                id: env("SIGNER_RP_ID")?,
                origins: env("SIGNER_ORIGINS")?
                    .split(',')
                    .map(String::from)
                    .collect(),
            },
            rules: env("SIGNER_RULES")?.into(),
            rules_authority: {
                let hex = env("SIGNER_RULES_AUTHORITY")?;
                let bytes: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("zz"), 16))
                    .collect::<Result<_, _>>()
                    .context("SIGNER_RULES_AUTHORITY : hex invalide")?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("SIGNER_RULES_AUTHORITY : 32 octets attendus"))?;
                ed25519_dalek::VerifyingKey::from_bytes(&arr)
                    .context("SIGNER_RULES_AUTHORITY invalide")?
            },
        })
    }
}

/// Ouvre un socket Unix (en supprimant un ancien fichier laissé par un arrêt brutal).
/// Accessible en écriture à tous : le vrai contrôle est l'UID de l'appelant, vérifié à chaque connexion.
fn listen(path: &Path) -> Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("impossible d'ouvrir {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

/// Attend la clé maître sur le socket d'amorçage. Réponse : 0 = coffre ouvert, 1 = clé refusée.
async fn unlock(cfg: &Config) -> Result<Vault> {
    let listener = listen(&cfg.boot_socket)?;
    info!(socket = %cfg.boot_socket.display(), "signer VERROUILLÉ : en attente de la clé maître");
    loop {
        let (mut stream, _) = listener.accept().await?;
        let uid = stream.peer_cred()?.uid();
        if uid != cfg.boot_uid {
            warn!(uid, "REFUS : livraison de clé par un appelant non autorisé");
            continue;
        }
        let mut key = Zeroizing::new([0u8; 32]);
        if stream.read_exact(key.as_mut()).await.is_err() {
            continue;
        }
        match Vault::open(&cfg.vault, MasterKey::from_bytes(*key)) {
            Ok(vault) => {
                let _ = stream.write_all(&[0]).await;
                drop(listener);
                let _ = std::fs::remove_file(&cfg.boot_socket);
                info!("coffre déverrouillé");
                return Ok(vault);
            }
            Err(VaultError::WrongMasterKey) => {
                warn!("REFUS : mauvaise clé maître");
                let _ = stream.write_all(&[1]).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cfg = Config::from_env()?;

    let vault = unlock(&cfg).await?;
    let factors = factors::Factors::new(webauthn::RelyingParty {
        id: cfg.rp.id.clone(),
        origins: cfg.rp.origins.clone(),
    });
    let rules = rules::RulesStore::new(cfg.rules.clone(), cfg.rules_authority);
    match rules.reload_if_changed() {
        Some(Ok(v)) => info!(version = v, "règles chargées"),
        Some(Err(e)) => warn!("REFUS : règles invalides ({e:?}) — aucun trade ne sera signé"),
        None => warn!("aucun fichier de règles — aucun trade ne sera signé"),
    }

    // Clé de test du ping de la chaîne (palier 1) : temporaire, sans aucun lien avec les wallets.
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|e| anyhow::anyhow!("aléa indisponible : {e}"))?;
    let ctx = Arc::new(Ctx {
        test_key: SigningKey::from_bytes(&seed),
        vault,
        factors,
        rules,
    });

    // Rechargement à chaud des règles : un fichier modifié ET correctement signé remplace l'ancien.
    let watcher = Arc::clone(&ctx);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tick.tick().await;
            match watcher.rules.reload_if_changed() {
                Some(Ok(v)) => info!(version = v, "règles rechargées"),
                Some(Err(e)) => warn!(
                    "REFUS : nouveau fichier de règles rejeté ({e:?}), anciennes règles conservées"
                ),
                None => {}
            }
        }
    });

    let listener = listen(&cfg.socket)?;
    info!(
        socket = %cfg.socket.display(),
        allowed_uid = cfg.allowed_uid,
        "scope-signer {} prêt",
        env!("CARGO_PKG_VERSION")
    );

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let ctx = Arc::clone(&ctx);
                let allowed = cfg.allowed_uid;
                tokio::spawn(async move {
                    if let Err(e) = serve(stream, &ctx, allowed).await {
                        warn!("connexion fermée : {e}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    let _ = std::fs::remove_file(&cfg.socket);
    Ok(())
}

/// Tout ce dont le signer a besoin pour répondre.
struct Ctx {
    test_key: SigningKey,
    vault: Vault,
    factors: factors::Factors,
    rules: rules::RulesStore,
}

/// Signe une transaction de trading : décodage, règles, propriétaire du wallet, puis signature.
fn sign_trade(
    ctx: &Ctx,
    user: [u8; 16],
    wallet: [u8; 32],
    expected_sol_out: u64,
    message: &[u8],
) -> Response {
    let msg = match solana::parse_message(message) {
        Ok(m) => m,
        Err(e) => {
            warn!("REFUS : transaction illisible ({e:?})");
            return Response::Failed(Failure::RuleViolation);
        }
    };
    let verdict = ctx
        .rules
        .with(|r| r.check_trade(&wallet, &msg, expected_sol_out));
    match verdict {
        None => return Response::Failed(Failure::NoRules),
        Some(Err(v)) => {
            warn!("REFUS : règle violée ({v:?})");
            return Response::Failed(Failure::RuleViolation);
        }
        Some(Ok(_)) => {}
    }
    match ctx.vault.signing_key(&user, &wallet) {
        Ok(key) => Response::Signature(key.sign(message).to_bytes()),
        Err(VaultError::NotFound) => Response::Failed(Failure::NotFound),
        Err(_) => Response::Failed(Failure::Internal),
    }
}

/// Signe un retrait de SOL : transaction conforme, wallet du compte, puis preuve PASSKEY.
fn sign_withdraw(
    ctx: &Ctx,
    req: (&[u8; 16], &[u8; 32], &[u8; 32], u64),
    message: &[u8],
    proof: &scope_protocol::signer_frame::Proof,
) -> Response {
    let (user, wallet, to, lamports) = req;
    let msg = match solana::parse_message(message) {
        Ok(m) => m,
        Err(e) => {
            warn!("REFUS : retrait illisible ({e:?})");
            return Response::Failed(Failure::RuleViolation);
        }
    };
    if let Err(v) = withdraw::check_withdraw(wallet, to, lamports, &msg) {
        warn!("REFUS : retrait non conforme ({v:?})");
        return Response::Failed(Failure::RuleViolation);
    }
    // Wallet du compte AVANT la preuve : on ne consomme pas le nonce pour rien.
    let key = match ctx.vault.signing_key(user, wallet) {
        Ok(k) => k,
        Err(VaultError::NotFound) => return Response::Failed(Failure::NotFound),
        Err(_) => return Response::Failed(Failure::Internal),
    };
    if let Err(f) = ctx
        .factors
        .verify_withdraw(&ctx.vault, user, wallet, to, lamports, proof)
    {
        warn!("REFUS : retrait sans preuve valide ({f:?})");
        return Response::Failed(f);
    }
    info!(lamports, "retrait signé");
    Response::Signature(key.sign(message).to_bytes())
}

/// Exécute une requête. Toute erreur devient une réponse : rien ne fait tomber le signer.
fn handle(req: Request, ctx: &Ctx) -> Response {
    let (test_key, vault, factors) = (&ctx.test_key, &ctx.vault, &ctx.factors);
    let fail = |e: VaultError| {
        Response::Failed(match e {
            VaultError::AlreadyExists => Failure::AlreadyExists,
            VaultError::InvalidKey => Failure::InvalidKey,
            _ => Failure::Internal,
        })
    };
    match req {
        Request::Pubkey => Response::Pubkey(test_key.verifying_key().to_bytes()),
        Request::SignTest(nonce) => Response::Signature(test_key.sign(&nonce).to_bytes()),
        Request::TransportKey => match vault.transport_secret() {
            Ok(s) => Response::TransportKey(x25519_dalek::PublicKey::from(&s).to_bytes()),
            Err(e) => fail(e),
        },
        Request::CreateWallet { user, to } => {
            let (pubkey, seed) = match vault.create_wallet(&user) {
                Ok(w) => w,
                Err(e) => return fail(e),
            };
            // Format Solana : graine (32) ‖ clé publique (32), scellé pour l'API seulement.
            let secret = Zeroizing::new([seed.as_slice(), pubkey.as_slice()].concat());
            match seal::seal(&to, &secret) {
                Ok(sealed) => Response::WalletCreated { pubkey, sealed },
                Err(_) => Response::Failed(Failure::Internal),
            }
        }
        Request::NewNonce { user } => factors
            .new_nonce(user)
            .map_or_else(Response::Failed, Response::Nonce),
        Request::RegisterPasskey {
            user,
            credential_id,
            cose,
            seal_to,
            proof,
        } => factors.register_passkey(vault, user, credential_id, cose, &seal_to, &proof),
        Request::VerifyRecovery { user, code } => factors.verify_recovery(vault, user, &code),
        Request::RegenerateRecovery {
            user,
            seal_to,
            proof,
        } => factors.regenerate_recovery(vault, user, &seal_to, &proof),
        Request::SignTrade {
            user,
            wallet,
            expected_sol_out,
            message,
        } => sign_trade(ctx, user, wallet, expected_sol_out, &message),
        Request::SignWithdraw {
            user,
            wallet,
            to,
            lamports,
            message,
            proof,
        } => sign_withdraw(ctx, (&user, &wallet, &to, lamports), &message, &proof),
        Request::TotpSetup {
            user,
            seal_to,
            proof,
        } => factors.totp_setup(vault, user, &seal_to, &proof),
        Request::TotpConfirm {
            user,
            code,
            seal_to,
        } => factors.totp_confirm(vault, user, &code, &seal_to),
        Request::VerifyTotp { user, code } => factors.verify_totp(vault, user, &code),
        Request::ImportWallet { user, sealed } => {
            let secret = match vault.transport_secret().map(|t| seal::open(&t, &sealed)) {
                Ok(Ok(s)) => s,
                Ok(Err(_)) => return Response::Failed(Failure::InvalidKey),
                Err(e) => return fail(e),
            };
            match vault.import_wallet(&user, &secret) {
                Ok(pubkey) => Response::WalletImported(pubkey),
                Err(e) => fail(e),
            }
        }
    }
}

async fn serve(mut stream: UnixStream, ctx: &Ctx, allowed_uid: u32) -> Result<()> {
    let uid = stream.peer_cred()?.uid();
    if uid != allowed_uid {
        warn!(uid, "REFUS : appelant non autorisé");
        return Ok(());
    }
    loop {
        let mut prefix = [0u8; 4];
        if stream.read_exact(&mut prefix).await.is_err() {
            return Ok(()); // le moteur a fermé la connexion
        }
        // Trame trop grande : on coupe sans rien lire de plus.
        let len = body_len(prefix).map_err(|e| anyhow::anyhow!("trame refusée : {e:?}"))?;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;

        let response = match Request::decode(&body) {
            Ok(req) => handle(req, ctx),
            Err(e) => {
                warn!("REFUS : requête invalide ({e:?})");
                Response::Refused
            }
        };
        let out = frame(&response.encode()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        stream.write_all(&out).await?;
    }
}
