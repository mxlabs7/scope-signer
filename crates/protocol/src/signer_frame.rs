//! Trames binaires du canal privé moteur ↔ signer (socket Unix).
//!
//! Format sur le fil : `[u32 big-endian : longueur][corps]`, longueur ≤ `MAX_FRAME`.
//! Corps d'une requête : `[version][opération][charge utile]`.
//! Corps d'une réponse : `[version][statut][charge utile]`.
//! Champs de taille variable : `[u16 big-endian : longueur][octets]`, avec une taille max par champ.
//! Aucun décodage ne doit jamais paniquer : toute entrée invalide renvoie une erreur,
//! et une trame doit être consommée EXACTEMENT (aucun octet en trop).

pub const VERSION: u8 = 1;
/// Taille max d'un corps de trame. Tout ce qui dépasse est refusé avant lecture.
pub const MAX_FRAME: usize = 4096;
/// Taille max d'un secret scellé (clé Solana de 64 octets + enveloppe).
pub const MAX_SEALED: usize = 256;

// Tailles max des champs variables.
const MAX_CRED_ID: usize = 255;
const MAX_COSE: usize = 512;
const MAX_AUTH_DATA: usize = 1024;
const MAX_CLIENT_DATA: usize = 2048;
const MAX_SIGNATURE: usize = 256;
const MAX_CODE: usize = 32;
const MAX_RECOVERY_SEALED: usize = 1024;

const OP_PUBKEY: u8 = 1;
const OP_SIGN_TEST: u8 = 2;
const OP_CREATE_WALLET: u8 = 3;
const OP_IMPORT_WALLET: u8 = 4;
const OP_TRANSPORT_KEY: u8 = 5;
const OP_NEW_NONCE: u8 = 6;
const OP_REGISTER_PASSKEY: u8 = 7;
const OP_VERIFY_RECOVERY: u8 = 8;
const OP_REGENERATE_RECOVERY: u8 = 9;
const OP_SIGN_TRADE: u8 = 10;
const OP_SIGN_WITHDRAW: u8 = 11;
const OP_TOTP_SETUP: u8 = 12;
const OP_TOTP_CONFIRM: u8 = 13;
const OP_VERIFY_TOTP: u8 = 14;
const OP_DELETE_WALLET: u8 = 15;
/// Taille max d'une transaction Solana.
pub const MAX_TX: usize = 1232;

const STATUS_OK: u8 = 0;
const STATUS_REFUSED: u8 = 1;
const STATUS_FAILED: u8 = 2;

pub type UserId = [u8; 16];

/// Réponse d'une passkey à un défi (`navigator.credentials.get`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Preuve qu'une action sensible vient bien du propriétaire du compte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// Aucune preuve : accepté UNIQUEMENT pour le tout premier facteur d'un compte.
    None,
    /// Passkey existante, sur un défi construit avec un nonce à usage unique émis par le signer.
    Passkey {
        nonce: [u8; 32],
        assertion: Assertion,
    },
    /// Code de secours (usage unique).
    Recovery { code: String },
    /// Code d'appli à 6 chiffres (TOTP), vérifié par le signer.
    Totp { code: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Clé publique de test du ping de la chaîne (palier 1).
    Pubkey,
    /// Signe un nonce de test de 32 octets (aucune transaction réelle).
    SignTest([u8; 32]),
    /// Crée un wallet ; la clé privée est renvoyée SCELLÉE pour la clé publique `to` (X25519).
    CreateWallet { user: UserId, to: [u8; 32] },
    /// Importe un wallet ; la clé privée arrive SCELLÉE pour la clé de transport du signer.
    ImportWallet { user: UserId, sealed: Vec<u8> },
    /// Clé publique de transport du signer (X25519), pour lui sceller un secret.
    TransportKey,
    /// Nonce à usage unique (5 min) pour construire le défi d'une action sensible.
    NewNonce { user: UserId },
    /// Enregistre une passkey dans le registre du signer. Au tout premier facteur, le signer génère
    /// les codes de secours et les renvoie scellés pour `seal_to`.
    RegisterPasskey {
        user: UserId,
        credential_id: Vec<u8>,
        cose: Vec<u8>,
        seal_to: [u8; 32],
        proof: Proof,
    },
    /// Consomme un code de secours (connexion de secours).
    VerifyRecovery { user: UserId, code: String },
    /// Remplace les codes de secours (preuve exigée) ; renvoyés scellés pour `seal_to`.
    RegenerateRecovery {
        user: UserId,
        seal_to: [u8; 32],
        proof: Proof,
    },
    /// Signe une transaction de TRADING, après vérification par les règles du signer.
    /// `expected_sol_out` : SOL attendu des ventes (borne haute de la fee de vente).
    SignTrade {
        user: UserId,
        wallet: [u8; 32],
        expected_sol_out: u64,
        message: Vec<u8>,
    },
    /// Signe un RETRAIT de SOL (`lamports` vers `to`), sur preuve PASSKEY uniquement. Le défi signé
    /// par la passkey couvre wallet, destination et montant ; la transaction ne doit faire que ça.
    SignWithdraw {
        user: UserId,
        wallet: [u8; 32],
        to: [u8; 32],
        lamports: u64,
        message: Vec<u8>,
        proof: Proof,
    },
    /// Prépare un code d'appli : le signer génère le secret et le renvoie SCELLÉ pour `seal_to`
    /// (affichage unique). Preuve exigée si le compte a déjà un facteur.
    TotpSetup {
        user: UserId,
        seal_to: [u8; 32],
        proof: Proof,
    },
    /// Active le code d'appli préparé, avec un premier code valide. Premier facteur du compte : le
    /// signer renvoie aussi les codes de secours scellés pour `seal_to`.
    TotpConfirm {
        user: UserId,
        code: String,
        seal_to: [u8; 32],
    },
    /// Vérifie un code d'appli (connexion web). Usage unique, anti force brute.
    VerifyTotp { user: UserId, code: String },
    /// Supprime DÉFINITIVEMENT un wallet du coffre, sur preuve (passkey liée à CE wallet, ou code d'appli).
    DeleteWallet {
        user: UserId,
        wallet: [u8; 32],
        proof: Proof,
    },
}

/// Raisons d'échec renvoyées par le signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    AlreadyExists = 1,
    InvalidKey = 2,
    Internal = 3,
    /// Le compte a déjà des facteurs : une preuve est exigée.
    NeedProof = 4,
    /// Preuve invalide (passkey, défi, nonce ou code de secours).
    BadProof = 5,
    /// Transaction refusée par les règles du signer.
    RuleViolation = 6,
    /// Wallet inconnu, ou n'appartenant pas à cet utilisateur.
    NotFound = 7,
    /// Aucune règle valide chargée.
    NoRules = 8,
    /// Trop de codes d'appli faux : bloqué temporairement (anti force brute).
    Locked = 9,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Pubkey([u8; 32]),
    Signature([u8; 64]),
    WalletCreated {
        pubkey: [u8; 32],
        sealed: Vec<u8>,
    },
    WalletImported([u8; 32]),
    TransportKey([u8; 32]),
    Nonce([u8; 32]),
    /// Passkey enregistrée ; codes de secours scellés s'il s'agissait du premier facteur.
    PasskeyRegistered {
        recovery_sealed: Option<Vec<u8>>,
    },
    /// Codes de secours scellés.
    Sealed(Vec<u8>),
    Ok,
    Failed(Failure),
    /// Le signer refuse (requête invalide ou interdite).
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooLarge,
    Truncated,
    BadVersion,
    UnknownOp,
    BadLength,
}

// ---------- Lecture / écriture des champs ----------

struct Writer(Vec<u8>);

impl Writer {
    fn new(head: u8) -> Self {
        Self(vec![VERSION, head])
    }
    fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    fn var(&mut self, b: &[u8]) -> &mut Self {
        // Les tailles max (≤ 2048) tiennent toujours sur 16 bits.
        let len = u16::try_from(b.len()).unwrap_or(u16::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(b);
        self
    }
    fn assertion(&mut self, a: &Assertion) -> &mut Self {
        self.var(&a.credential_id)
            .var(&a.authenticator_data)
            .var(&a.client_data_json)
            .var(&a.signature)
    }
    fn proof(&mut self, p: &Proof) -> &mut Self {
        match p {
            Proof::None => self.raw(&[0]),
            Proof::Passkey { nonce, assertion } => self.raw(&[1]).raw(nonce).assertion(assertion),
            Proof::Recovery { code } => self.raw(&[2]).var(code.as_bytes()),
            Proof::Totp { code } => self.raw(&[3]).var(code.as_bytes()),
        }
    }
    fn done(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        if self.0.len() < n {
            return Err(FrameError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        self.take(N)?.try_into().map_err(|_| FrameError::BadLength)
    }
    fn byte(&mut self) -> Result<u8, FrameError> {
        Ok(self.array::<1>()?[0])
    }
    fn var(&mut self, max: usize) -> Result<Vec<u8>, FrameError> {
        let len = u16::from_be_bytes(self.array()?) as usize;
        if len > max {
            return Err(FrameError::BadLength);
        }
        Ok(self.take(len)?.to_vec())
    }
    fn text(&mut self, max: usize) -> Result<String, FrameError> {
        String::from_utf8(self.var(max)?).map_err(|_| FrameError::BadLength)
    }
    fn assertion(&mut self) -> Result<Assertion, FrameError> {
        Ok(Assertion {
            credential_id: self.var(MAX_CRED_ID)?,
            authenticator_data: self.var(MAX_AUTH_DATA)?,
            client_data_json: self.var(MAX_CLIENT_DATA)?,
            signature: self.var(MAX_SIGNATURE)?,
        })
    }
    fn proof(&mut self) -> Result<Proof, FrameError> {
        match self.byte()? {
            0 => Ok(Proof::None),
            1 => Ok(Proof::Passkey {
                nonce: self.array()?,
                assertion: self.assertion()?,
            }),
            2 => Ok(Proof::Recovery {
                code: self.text(MAX_CODE)?,
            }),
            3 => Ok(Proof::Totp {
                code: self.text(MAX_CODE)?,
            }),
            _ => Err(FrameError::UnknownOp),
        }
    }
    /// Une trame doit être consommée exactement.
    fn end<T>(self, value: T) -> Result<T, FrameError> {
        if self.0.is_empty() {
            Ok(value)
        } else {
            Err(FrameError::BadLength)
        }
    }
}

fn sealed(b: &[u8]) -> Result<Vec<u8>, FrameError> {
    if b.is_empty() || b.len() > MAX_SEALED {
        return Err(FrameError::BadLength);
    }
    Ok(b.to_vec())
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Request::Pubkey => Writer::new(OP_PUBKEY).done(),
            Request::SignTest(nonce) => Writer::new(OP_SIGN_TEST).raw(nonce).done(),
            Request::CreateWallet { user, to } => {
                Writer::new(OP_CREATE_WALLET).raw(user).raw(to).done()
            }
            Request::ImportWallet { user, sealed } => {
                Writer::new(OP_IMPORT_WALLET).raw(user).raw(sealed).done()
            }
            Request::TransportKey => Writer::new(OP_TRANSPORT_KEY).done(),
            Request::NewNonce { user } => Writer::new(OP_NEW_NONCE).raw(user).done(),
            Request::RegisterPasskey {
                user,
                credential_id,
                cose,
                seal_to,
                proof,
            } => Writer::new(OP_REGISTER_PASSKEY)
                .raw(user)
                .var(credential_id)
                .var(cose)
                .raw(seal_to)
                .proof(proof)
                .done(),
            Request::VerifyRecovery { user, code } => Writer::new(OP_VERIFY_RECOVERY)
                .raw(user)
                .var(code.as_bytes())
                .done(),
            Request::RegenerateRecovery {
                user,
                seal_to,
                proof,
            } => Writer::new(OP_REGENERATE_RECOVERY)
                .raw(user)
                .raw(seal_to)
                .proof(proof)
                .done(),
            Request::SignTrade {
                user,
                wallet,
                expected_sol_out,
                message,
            } => Writer::new(OP_SIGN_TRADE)
                .raw(user)
                .raw(wallet)
                .raw(&expected_sol_out.to_be_bytes())
                .var(message)
                .done(),
            Request::SignWithdraw {
                user,
                wallet,
                to,
                lamports,
                message,
                proof,
            } => Writer::new(OP_SIGN_WITHDRAW)
                .raw(user)
                .raw(wallet)
                .raw(to)
                .raw(&lamports.to_be_bytes())
                .var(message)
                .proof(proof)
                .done(),
            Request::TotpSetup {
                user,
                seal_to,
                proof,
            } => Writer::new(OP_TOTP_SETUP)
                .raw(user)
                .raw(seal_to)
                .proof(proof)
                .done(),
            Request::TotpConfirm {
                user,
                code,
                seal_to,
            } => Writer::new(OP_TOTP_CONFIRM)
                .raw(user)
                .var(code.as_bytes())
                .raw(seal_to)
                .done(),
            Request::VerifyTotp { user, code } => Writer::new(OP_VERIFY_TOTP)
                .raw(user)
                .var(code.as_bytes())
                .done(),
            Request::DeleteWallet {
                user,
                wallet,
                proof,
            } => Writer::new(OP_DELETE_WALLET)
                .raw(user)
                .raw(wallet)
                .proof(proof)
                .done(),
        }
    }

    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        let (op, p) = header(body)?;
        let mut r = Reader(p);
        match op {
            OP_PUBKEY => r.end(Request::Pubkey),
            OP_TRANSPORT_KEY => r.end(Request::TransportKey),
            OP_SIGN_TEST => {
                let nonce = r.array()?;
                r.end(Request::SignTest(nonce))
            }
            OP_CREATE_WALLET => {
                let (user, to) = (r.array()?, r.array()?);
                r.end(Request::CreateWallet { user, to })
            }
            OP_IMPORT_WALLET => {
                let user = r.array()?;
                let rest = sealed(r.0)?;
                Ok(Request::ImportWallet { user, sealed: rest })
            }
            OP_NEW_NONCE => {
                let user = r.array()?;
                r.end(Request::NewNonce { user })
            }
            OP_REGISTER_PASSKEY => {
                let user = r.array()?;
                let credential_id = r.var(MAX_CRED_ID)?;
                let cose = r.var(MAX_COSE)?;
                let seal_to = r.array()?;
                let proof = r.proof()?;
                if credential_id.is_empty() || cose.is_empty() {
                    return Err(FrameError::BadLength);
                }
                r.end(Request::RegisterPasskey {
                    user,
                    credential_id,
                    cose,
                    seal_to,
                    proof,
                })
            }
            OP_VERIFY_RECOVERY => {
                let user = r.array()?;
                let code = r.text(MAX_CODE)?;
                r.end(Request::VerifyRecovery { user, code })
            }
            OP_REGENERATE_RECOVERY => {
                let (user, seal_to) = (r.array()?, r.array()?);
                let proof = r.proof()?;
                r.end(Request::RegenerateRecovery {
                    user,
                    seal_to,
                    proof,
                })
            }
            OP_SIGN_TRADE => {
                let (user, wallet) = (r.array()?, r.array()?);
                let expected_sol_out = u64::from_be_bytes(r.array()?);
                let message = r.var(MAX_TX)?;
                if message.is_empty() {
                    return Err(FrameError::BadLength);
                }
                r.end(Request::SignTrade {
                    user,
                    wallet,
                    expected_sol_out,
                    message,
                })
            }
            OP_SIGN_WITHDRAW => {
                let (user, wallet, to) = (r.array()?, r.array()?, r.array()?);
                let lamports = u64::from_be_bytes(r.array()?);
                let message = r.var(MAX_TX)?;
                let proof = r.proof()?;
                if message.is_empty() {
                    return Err(FrameError::BadLength);
                }
                r.end(Request::SignWithdraw {
                    user,
                    wallet,
                    to,
                    lamports,
                    message,
                    proof,
                })
            }
            OP_TOTP_SETUP => {
                let (user, seal_to) = (r.array()?, r.array()?);
                let proof = r.proof()?;
                r.end(Request::TotpSetup {
                    user,
                    seal_to,
                    proof,
                })
            }
            OP_TOTP_CONFIRM => {
                let user = r.array()?;
                let code = r.text(MAX_CODE)?;
                let seal_to = r.array()?;
                r.end(Request::TotpConfirm {
                    user,
                    code,
                    seal_to,
                })
            }
            OP_VERIFY_TOTP => {
                let user = r.array()?;
                let code = r.text(MAX_CODE)?;
                r.end(Request::VerifyTotp { user, code })
            }
            OP_DELETE_WALLET => {
                let (user, wallet) = (r.array()?, r.array()?);
                let proof = r.proof()?;
                r.end(Request::DeleteWallet {
                    user,
                    wallet,
                    proof,
                })
            }
            _ => Err(FrameError::UnknownOp),
        }
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Response::Pubkey(k)
            | Response::WalletImported(k)
            | Response::TransportKey(k)
            | Response::Nonce(k) => Writer::new(STATUS_OK).raw(k).done(),
            Response::Signature(s) => Writer::new(STATUS_OK).raw(s).done(),
            Response::WalletCreated { pubkey, sealed } => {
                Writer::new(STATUS_OK).raw(pubkey).raw(sealed).done()
            }
            Response::PasskeyRegistered {
                recovery_sealed: None,
            } => Writer::new(STATUS_OK).raw(&[0]).done(),
            Response::PasskeyRegistered {
                recovery_sealed: Some(s),
            } => Writer::new(STATUS_OK).raw(&[1]).var(s).done(),
            Response::Sealed(s) => Writer::new(STATUS_OK).var(s).done(),
            Response::Ok => Writer::new(STATUS_OK).done(),
            Response::Failed(f) => Writer::new(STATUS_FAILED).raw(&[*f as u8]).done(),
            Response::Refused => Writer::new(STATUS_REFUSED).done(),
        }
    }

    /// La réponse attendue dépend de la requête envoyée.
    pub fn decode(body: &[u8], to: &Request) -> Result<Self, FrameError> {
        let (status, p) = header(body)?;
        let mut r = Reader(p);
        match status {
            STATUS_REFUSED => r.end(Response::Refused),
            STATUS_FAILED => {
                let f = match r.byte()? {
                    1 => Failure::AlreadyExists,
                    2 => Failure::InvalidKey,
                    3 => Failure::Internal,
                    4 => Failure::NeedProof,
                    5 => Failure::BadProof,
                    6 => Failure::RuleViolation,
                    7 => Failure::NotFound,
                    8 => Failure::NoRules,
                    9 => Failure::Locked,
                    _ => return Err(FrameError::BadLength),
                };
                r.end(Response::Failed(f))
            }
            STATUS_OK => match to {
                Request::Pubkey => {
                    let k = r.array()?;
                    r.end(Response::Pubkey(k))
                }
                Request::SignTest(_) | Request::SignTrade { .. } | Request::SignWithdraw { .. } => {
                    let s = r.array()?;
                    r.end(Response::Signature(s))
                }
                Request::TransportKey => {
                    let k = r.array()?;
                    r.end(Response::TransportKey(k))
                }
                Request::ImportWallet { .. } => {
                    let k = r.array()?;
                    r.end(Response::WalletImported(k))
                }
                Request::NewNonce { .. } => {
                    let n = r.array()?;
                    r.end(Response::Nonce(n))
                }
                Request::CreateWallet { .. } => {
                    let pubkey = r.array()?;
                    let rest = sealed(r.0)?;
                    Ok(Response::WalletCreated {
                        pubkey,
                        sealed: rest,
                    })
                }
                Request::RegisterPasskey { .. } => match r.byte()? {
                    0 => r.end(Response::PasskeyRegistered {
                        recovery_sealed: None,
                    }),
                    1 => {
                        let s = r.var(MAX_RECOVERY_SEALED)?;
                        r.end(Response::PasskeyRegistered {
                            recovery_sealed: Some(s),
                        })
                    }
                    _ => Err(FrameError::BadLength),
                },
                Request::TotpSetup { .. } => {
                    let s = r.var(MAX_RECOVERY_SEALED)?;
                    r.end(Response::Sealed(s))
                }
                // Codes de secours scellés (premier facteur) ou rien.
                Request::TotpConfirm { .. } if r.0.is_empty() => Ok(Response::Ok),
                Request::TotpConfirm { .. } => {
                    let s = r.var(MAX_RECOVERY_SEALED)?;
                    r.end(Response::Sealed(s))
                }
                Request::RegenerateRecovery { .. } => {
                    let s = r.var(MAX_RECOVERY_SEALED)?;
                    r.end(Response::Sealed(s))
                }
                Request::VerifyRecovery { .. }
                | Request::VerifyTotp { .. }
                | Request::DeleteWallet { .. } => r.end(Response::Ok),
            },
            _ => Err(FrameError::UnknownOp),
        }
    }
}

/// Ajoute le préfixe de longueur.
pub fn frame(body: &[u8]) -> Result<Vec<u8>, FrameError> {
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge)?;
    let mut out = len.to_be_bytes().to_vec();
    out.extend_from_slice(body);
    Ok(out)
}

/// Lit le préfixe de longueur et vérifie la limite AVANT d'allouer quoi que ce soit.
pub fn body_len(prefix: [u8; 4]) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    Ok(len)
}

fn header(body: &[u8]) -> Result<(u8, &[u8]), FrameError> {
    match body {
        [v, _, ..] if *v != VERSION => Err(FrameError::BadVersion),
        [_, op, rest @ ..] => Ok((*op, rest)),
        _ => Err(FrameError::Truncated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assertion() -> Assertion {
        Assertion {
            credential_id: vec![1; 16],
            authenticator_data: vec![2; 37],
            client_data_json: b"{}".to_vec(),
            signature: vec![3; 70],
        }
    }

    fn requests() -> Vec<Request> {
        vec![
            Request::Pubkey,
            Request::SignTest([7; 32]),
            Request::CreateWallet {
                user: [1; 16],
                to: [2; 32],
            },
            Request::ImportWallet {
                user: [1; 16],
                sealed: vec![9; 140],
            },
            Request::TransportKey,
            Request::NewNonce { user: [1; 16] },
            Request::RegisterPasskey {
                user: [1; 16],
                credential_id: vec![4; 16],
                cose: vec![5; 77],
                seal_to: [6; 32],
                proof: Proof::None,
            },
            Request::RegisterPasskey {
                user: [1; 16],
                credential_id: vec![4; 16],
                cose: vec![5; 77],
                seal_to: [6; 32],
                proof: Proof::Passkey {
                    nonce: [8; 32],
                    assertion: assertion(),
                },
            },
            Request::VerifyRecovery {
                user: [1; 16],
                code: "ABCDE-12345".into(),
            },
            Request::RegenerateRecovery {
                user: [1; 16],
                seal_to: [6; 32],
                proof: Proof::Recovery {
                    code: "ABCDE-12345".into(),
                },
            },
            Request::SignTrade {
                user: [1; 16],
                wallet: [2; 32],
                expected_sol_out: 123,
                message: vec![1; 400],
            },
            Request::SignWithdraw {
                user: [1; 16],
                wallet: [2; 32],
                to: [3; 32],
                lamports: 1_500_000_000,
                message: vec![1; 200],
                proof: Proof::Passkey {
                    nonce: [8; 32],
                    assertion: assertion(),
                },
            },
            Request::TotpSetup {
                user: [1; 16],
                seal_to: [6; 32],
                proof: Proof::Totp {
                    code: "123456".into(),
                },
            },
            Request::TotpConfirm {
                user: [1; 16],
                code: "654321".into(),
                seal_to: [6; 32],
            },
            Request::VerifyTotp {
                user: [1; 16],
                code: "111111".into(),
            },
            Request::DeleteWallet {
                user: [1; 16],
                wallet: [2; 32],
                proof: Proof::Passkey {
                    nonce: [8; 32],
                    assertion: assertion(),
                },
            },
        ]
    }

    #[test]
    fn aller_retour_requetes() {
        for req in requests() {
            assert_eq!(Request::decode(&req.encode()), Ok(req));
        }
    }

    #[test]
    fn aller_retour_reponses() {
        let reqs = requests();
        let cases = [
            (Response::Pubkey([1; 32]), 0),
            (Response::Signature([2; 64]), 1),
            (
                Response::WalletCreated {
                    pubkey: [3; 32],
                    sealed: vec![4; 140],
                },
                2,
            ),
            (Response::WalletImported([5; 32]), 3),
            (Response::TransportKey([6; 32]), 4),
            (Response::Nonce([7; 32]), 5),
            (
                Response::PasskeyRegistered {
                    recovery_sealed: None,
                },
                6,
            ),
            (
                Response::PasskeyRegistered {
                    recovery_sealed: Some(vec![9; 300]),
                },
                6,
            ),
            (Response::Ok, 8),
            (Response::Sealed(vec![9; 300]), 9),
            (Response::Failed(Failure::BadProof), 7),
            (Response::Refused, 1),
            (Response::Signature([5; 64]), 10),
            (Response::Failed(Failure::RuleViolation), 10),
            (Response::Signature([6; 64]), 11),
            (Response::Failed(Failure::BadProof), 11),
            (Response::Sealed(vec![7; 80]), 12),
            (Response::Ok, 13),
            (Response::Sealed(vec![7; 300]), 13),
            (Response::Ok, 14),
            (Response::Failed(Failure::Locked), 14),
        ];
        for (resp, i) in cases {
            assert_eq!(Response::decode(&resp.encode(), &reqs[i]), Ok(resp));
        }
    }

    #[test]
    fn refuse_les_tailles_anormales_et_les_octets_en_trop() {
        assert_eq!(
            body_len((MAX_FRAME as u32 + 1).to_be_bytes()),
            Err(FrameError::TooLarge)
        );
        assert_eq!(frame(&vec![0; MAX_FRAME + 1]), Err(FrameError::TooLarge));
        let huge = Request::ImportWallet {
            user: [1; 16],
            sealed: vec![0; MAX_SEALED + 1],
        };
        assert_eq!(Request::decode(&huge.encode()), Err(FrameError::BadLength));
        let mut extra = Request::NewNonce { user: [1; 16] }.encode();
        extra.push(0);
        assert_eq!(Request::decode(&extra), Err(FrameError::BadLength));
        let long_code = Request::VerifyRecovery {
            user: [1; 16],
            code: "X".repeat(MAX_CODE + 1),
        };
        assert_eq!(
            Request::decode(&long_code.encode()),
            Err(FrameError::BadLength)
        );
    }

    /// Inondation : des centaines de milliers d'entrées pseudo-aléatoires, aucune panique.
    #[test]
    fn aucune_panique_sur_entree_arbitraire() {
        let reqs = requests();
        // On part aussi de trames VALIDES mutées octet par octet : c'est là que se cachent les bugs.
        let valid: Vec<Vec<u8>> = reqs.iter().map(Request::encode).collect();
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for i in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut bytes = if i % 2 == 0 {
                valid[i % valid.len()].clone()
            } else {
                (0..(x % 300) as usize)
                    .map(|j| (x >> (j % 8 * 8)) as u8 ^ j as u8)
                    .collect()
            };
            if !bytes.is_empty() {
                let pos = (x as usize) % bytes.len();
                bytes[pos] ^= (x >> 32) as u8;
                if x.is_multiple_of(5) {
                    bytes.truncate(pos);
                }
            }
            let _ = Request::decode(&bytes);
            for r in &reqs {
                let _ = Response::decode(&bytes, r);
            }
        }
    }
}
