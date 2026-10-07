//! Règles du signer : ce qu'une transaction de TRADING a le droit de faire.
//!
//! Les règles sont des DONNÉES (fichier JSON) signées par une clé d'autorité tenue hors du serveur
//! (gardée hors ligne en production) : pump.fun change souvent, on met à jour le fichier sans redéployer le signer.
//! Un fichier dont la signature est invalide est refusé et les règles précédentes restent en vigueur.
//!
//! Une transaction de trading est signée SEULEMENT si :
//! - le wallet est le seul signataire et paie les frais ;
//! - chaque instruction est reconnue : budget de calcul, achat/vente pump.fun listés dans les règles,
//!   création de compte de tokens, wrap/unwrap SOL ;
//! - les comptes de tokens de l'acheteur/vendeur désignés par la règle sont SES comptes associés
//!   (adresse dérivée du wallet, du mint et du programme de token officiel) : un moteur compromis ne
//!   peut pas faire livrer les tokens achetés ou le SOL d'une vente sur un autre compte ;
//! - le SOL ne sort que vers : le wallet de fees de Scope, un compte de tip Jito, ou le compte WSOL
//!   du wallet lui-même ;
//! - frais de priorité et tip Jito plafonnés (`max_priority_lamports`, `max_tip_lamports`) : un moteur
//!   compromis ne peut pas brûler le SOL du wallet en frais ;
//! - rien ne peut donner le contrôle d'un compte (Approve, SetAuthority, Assign… sont refusés) ;
//! - la fee est exacte à l'achat (fee_bps du SOL dépensé) et encadrée à la vente
//!   (entre fee_bps du minimum garanti et fee_bps du montant attendu).

use std::collections::HashSet;

use serde::Deserialize;

use scope_solana::{self as solana, Message, Pubkey};

const SYSTEM_PROGRAM: Pubkey = [0; 32];
const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    version: u32,
    fee_wallet: String,
    fee_bps: u16,
    jito_tip_accounts: Vec<String>,
    /// Plafond des frais de priorité d'un trade (limite de calcul × prix), en lamports.
    max_priority_lamports: u64,
    /// Plafond du tip Jito d'un trade, en lamports.
    max_tip_lamports: u64,
    instructions: Vec<IxRuleFile>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// `sol_offset` = SOL dépensé (exact ou maximum), base de la fee.
    Buy,
    /// `sol_offset` = SOL minimum garanti en sortie.
    Sell,
    /// Entretien sans montant ni fee (fermeture des compteurs pump.fun, réclamation du cashback) : le
    /// SOL récupéré revient forcément à l'utilisateur (`user_index` = le wallet, comptes de tokens à lui).
    Maintenance,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IxRuleFile {
    name: String,
    program: String,
    /// 8 octets en hex.
    discriminator: String,
    kind: Kind,
    /// Position du compte « acheteur / vendeur » dans l'instruction : doit être le wallet.
    user_index: usize,
    /// Position (octets) du montant de SOL (u64 little-endian) dans les données.
    sol_offset: usize,
    /// Comptes de tokens de l'utilisateur : `[compte, mint, programme de token]` (positions dans
    /// l'instruction). Chaque compte doit être le compte associé du wallet pour ce mint.
    token_accounts: Vec<[usize; 3]>,
}

struct IxRule {
    name: String,
    program: Pubkey,
    discriminator: [u8; 8],
    kind: Kind,
    user_index: usize,
    sol_offset: usize,
    token_accounts: Vec<[usize; 3]>,
}

pub struct Rules {
    pub version: u32,
    fee_wallet: Pubkey,
    fee_bps: u64,
    tips: HashSet<Pubkey>,
    max_priority: u64,
    max_tip: u64,
    ixs: Vec<IxRule>,
    compute_budget: Pubkey,
    token: Pubkey,
    token_2022: Pubkey,
    ata: Pubkey,
    wsol: Pubkey,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RulesError {
    BadSignature,
    BadFile(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Violation {
    NotSoleSigner,
    WrongFeePayer,
    ProgramNotAllowed(String),
    InstructionNotAllowed(&'static str),
    TransferNotAllowed,
    WrongUser(String),
    /// Un compte de tokens de l'instruction n'appartient pas au wallet.
    ForeignTokenAccount(String),
    NoTrade,
    PriorityTooHigh(u64),
    TipTooHigh(u64),
    BadFee {
        expected_min: u64,
        expected_max: u64,
        found: u64,
    },
    Overflow,
}

/// Résumé de ce que fait une transaction acceptée.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct TradeSummary {
    pub buy_lamports: u64,
    pub sell_min_lamports: u64,
    pub fee: u64,
    pub tip: u64,
}

fn key(s: &str) -> Result<Pubkey, RulesError> {
    solana::pubkey(s).ok_or_else(|| RulesError::BadFile(format!("adresse invalide : {s}")))
}

impl Rules {
    /// Charge un fichier de règles APRÈS avoir vérifié sa signature par la clé d'autorité.
    pub fn load(
        json: &[u8],
        signature: &[u8; 64],
        authority: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self, RulesError> {
        authority
            .verify_strict(json, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| RulesError::BadSignature)?;
        let f: RulesFile =
            serde_json::from_slice(json).map_err(|e| RulesError::BadFile(e.to_string()))?;
        if f.fee_bps > 1_000 {
            return Err(RulesError::BadFile("fee_bps > 10 %".into()));
        }
        let ixs = f
            .instructions
            .into_iter()
            .map(|r| {
                let disc: Vec<u8> = (0..r.discriminator.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(r.discriminator.get(i..i + 2).unwrap_or("zz"), 16))
                    .collect::<Result<_, _>>()
                    .map_err(|_| {
                        RulesError::BadFile(format!("discriminateur invalide : {}", r.name))
                    })?;
                Ok(IxRule {
                    program: key(&r.program)?,
                    discriminator: disc
                        .try_into()
                        .map_err(|_| RulesError::BadFile(format!("discriminateur : {}", r.name)))?,
                    kind: r.kind,
                    user_index: r.user_index,
                    sol_offset: r.sol_offset,
                    token_accounts: r.token_accounts,
                    name: r.name,
                })
            })
            .collect::<Result<Vec<_>, RulesError>>()?;
        Ok(Self {
            version: f.version,
            fee_wallet: key(&f.fee_wallet)?,
            fee_bps: u64::from(f.fee_bps),
            tips: f
                .jito_tip_accounts
                .iter()
                .map(|t| key(t))
                .collect::<Result<_, _>>()?,
            max_priority: f.max_priority_lamports,
            max_tip: f.max_tip_lamports,
            ixs,
            compute_budget: key(COMPUTE_BUDGET)?,
            token: key(solana::TOKEN_PROGRAM)?,
            token_2022: key(TOKEN_2022)?,
            ata: key(solana::ATA_PROGRAM)?,
            wsol: key(solana::WSOL_MINT)?,
        })
    }

    fn fee_of(&self, lamports: u64) -> Result<u64, Violation> {
        lamports
            .checked_mul(self.fee_bps)
            .map(|x| x / 10_000)
            .ok_or(Violation::Overflow)
    }

    /// Vérifie une transaction de trading pour `wallet`. `expected_sol_out` : SOL attendu des ventes.
    pub fn check_trade(
        &self,
        wallet: &Pubkey,
        msg: &Message,
        expected_sol_out: u64,
    ) -> Result<TradeSummary, Violation> {
        if msg.required_signatures != 1 {
            return Err(Violation::NotSoleSigner);
        }
        if msg.accounts.first() != Some(wallet) {
            return Err(Violation::WrongFeePayer);
        }
        let wsol_ata = [self.token, self.token_2022]
            .iter()
            .filter_map(|tp| solana::associated_token_address(wallet, &self.wsol, tp))
            .collect::<Vec<_>>();
        let mut sum = TradeSummary::default();
        let mut budget = crate::budget::Budget::default();
        let mut trades = 0usize;
        // Fermetures de comptes de tokens du wallet (le SOL du loyer revient au wallet).
        let mut closes = 0usize;
        let add = |a: u64, b: u64| a.checked_add(b).ok_or(Violation::Overflow);

        for ix in &msg.instructions {
            let d = &ix.data;
            if ix.program == self.compute_budget {
                // SetComputeUnitLimit / SetComputeUnitPrice, une fois chacun.
                budget
                    .read(d)
                    .map_err(|()| Violation::InstructionNotAllowed("compute budget"))?;
            } else if ix.program == SYSTEM_PROGRAM {
                // Seul le transfert (2) est permis : CreateAccount, Assign, Allocate… sont refusés.
                if d.len() != 12 || d[..4] != [2, 0, 0, 0] {
                    return Err(Violation::InstructionNotAllowed("system"));
                }
                let lamports = u64::from_le_bytes(
                    d[4..12]
                        .try_into()
                        .map_err(|_| Violation::TransferNotAllowed)?,
                );
                let (from, to) = (ix.accounts.first(), ix.accounts.get(1));
                if from != Some(wallet) {
                    return Err(Violation::TransferNotAllowed);
                }
                match to {
                    Some(t) if *t == self.fee_wallet => sum.fee = add(sum.fee, lamports)?,
                    Some(t) if self.tips.contains(t) => sum.tip = add(sum.tip, lamports)?,
                    Some(t) if wsol_ata.contains(t) => {} // wrap SOL vers son propre compte WSOL
                    _ => return Err(Violation::TransferNotAllowed),
                }
            } else if ix.program == self.token || ix.program == self.token_2022 {
                match d.first() {
                    // SyncNative sur son propre compte WSOL.
                    Some(17) if ix.accounts.first().is_some_and(|a| wsol_ata.contains(a)) => {}
                    // CloseAccount : le SOL revient au wallet, qui en est le propriétaire.
                    Some(9)
                        if ix.accounts.get(1) == Some(wallet)
                            && ix.accounts.get(2) == Some(wallet) =>
                    {
                        closes += 1;
                    }
                    _ => return Err(Violation::InstructionNotAllowed("token")),
                }
            } else if ix.program == self.ata {
                // Create (vide ou 0) / CreateIdempotent (1) : payé par le wallet, pour le wallet.
                let ok = matches!(d.as_slice(), [] | [0] | [1])
                    && ix.accounts.first() == Some(wallet)
                    && ix.accounts.get(2) == Some(wallet);
                if !ok {
                    return Err(Violation::InstructionNotAllowed("associated token account"));
                }
            } else if let Some(rule) = self
                .ixs
                .iter()
                .find(|r| r.program == ix.program && d.len() >= 8 && d[..8] == r.discriminator)
            {
                if ix.accounts.get(rule.user_index) != Some(wallet) {
                    return Err(Violation::WrongUser(rule.name.clone()));
                }
                for &[acc, mint, program] in &rule.token_accounts {
                    let own = match (ix.accounts.get(mint), ix.accounts.get(program)) {
                        (Some(m), Some(tp)) if *tp == self.token || *tp == self.token_2022 => {
                            solana::associated_token_address(wallet, m, tp)
                        }
                        _ => None,
                    };
                    if own.is_none() || ix.accounts.get(acc) != own.as_ref() {
                        return Err(Violation::ForeignTokenAccount(rule.name.clone()));
                    }
                }
                let amount = if rule.kind == Kind::Maintenance {
                    0
                } else {
                    d.get(rule.sol_offset..rule.sol_offset + 8)
                        .and_then(|b| b.try_into().ok())
                        .map(u64::from_le_bytes)
                        .ok_or(Violation::InstructionNotAllowed(
                            "données d'instruction trop courtes",
                        ))?
                };
                match rule.kind {
                    Kind::Buy => sum.buy_lamports = add(sum.buy_lamports, amount)?,
                    Kind::Sell => sum.sell_min_lamports = add(sum.sell_min_lamports, amount)?,
                    Kind::Maintenance => {}
                }
                trades += 1;
            } else {
                return Err(Violation::ProgramNotAllowed(bs58_short(&ix.program)));
            }
        }

        // Sans trade, une seule chose est permise : fermer des comptes de tokens vides du wallet pour en
        // récupérer le loyer (page Reclaim). Le SOL revient au wallet ; ni tip, ni fee, ni transfert sortant.
        if trades == 0 && (closes == 0 || sum.tip > 0 || sum.fee > 0) {
            return Err(Violation::NoTrade);
        }
        if budget.priority_lamports() > self.max_priority {
            return Err(Violation::PriorityTooHigh(budget.priority_lamports()));
        }
        if sum.tip > self.max_tip {
            return Err(Violation::TipTooHigh(sum.tip));
        }
        let buy_fee = self.fee_of(sum.buy_lamports)?;
        let (sell_lo, sell_hi) = if sum.sell_min_lamports > 0 || expected_sol_out > 0 {
            (
                self.fee_of(sum.sell_min_lamports)?,
                self.fee_of(expected_sol_out.max(sum.sell_min_lamports))?,
            )
        } else {
            (0, 0)
        };
        let (min, max) = (add(buy_fee, sell_lo)?, add(buy_fee, sell_hi)?);
        if sum.fee < min || sum.fee > max {
            return Err(Violation::BadFee {
                expected_min: min,
                expected_max: max,
                found: sum.fee,
            });
        }
        Ok(sum)
    }
}

fn bs58_short(k: &Pubkey) -> String {
    k.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Règles en vigueur, rechargées à chaud depuis le fichier si (et seulement si) sa signature est valide.
pub struct RulesStore {
    path: std::path::PathBuf,
    authority: ed25519_dalek::VerifyingKey,
    current: std::sync::RwLock<Option<Rules>>,
    stamp: std::sync::Mutex<Option<(std::time::SystemTime, std::time::SystemTime)>>,
}

impl RulesStore {
    pub fn new(path: std::path::PathBuf, authority: ed25519_dalek::VerifyingKey) -> Self {
        Self {
            path,
            authority,
            current: std::sync::RwLock::new(None),
            stamp: std::sync::Mutex::new(None),
        }
    }

    fn sig_path(&self) -> std::path::PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".sig");
        p.into()
    }

    /// Recharge si le fichier ou sa signature ont changé. `None` : rien de nouveau (ou fichier absent).
    pub fn reload_if_changed(&self) -> Option<Result<u32, RulesError>> {
        let mtime = |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        let stamp = (mtime(&self.path)?, mtime(&self.sig_path())?);
        let mut last = self.stamp.lock().ok()?;
        if *last == Some(stamp) {
            return None;
        }
        *last = Some(stamp);
        let load = || -> Result<Rules, RulesError> {
            let json = std::fs::read(&self.path).map_err(|e| RulesError::BadFile(e.to_string()))?;
            let hex = std::fs::read_to_string(self.sig_path())
                .map_err(|e| RulesError::BadFile(e.to_string()))?;
            let hex = hex.trim();
            let sig: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("zz"), 16))
                .collect::<Result<_, _>>()
                .map_err(|_| RulesError::BadSignature)?;
            let sig: [u8; 64] = sig.try_into().map_err(|_| RulesError::BadSignature)?;
            Rules::load(&json, &sig, &self.authority)
        };
        Some(load().and_then(|rules| {
            let v = rules.version;
            *self
                .current
                .write()
                .map_err(|_| RulesError::BadFile("verrou".into()))? = Some(rules);
            Ok(v)
        }))
    }

    /// Applique `f` aux règles en vigueur ; `None` si aucune règle valide n'est chargée.
    pub fn with<R>(&self, f: impl FnOnce(&Rules) -> R) -> Option<R> {
        self.current.read().ok()?.as_ref().map(f)
    }
}

#[cfg(test)]
#[path = "attack_tests.rs"]
mod attack_tests;

#[cfg(test)]
pub mod testing {
    //! Règles et transactions de test.
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    pub const PUMP: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
    pub const FEE_WALLET: &str = "4u2Ns6VoqzScrdXz3kwqDaVq6M3sjSLM9Bw4GYYfUEEF";
    pub const TIP: &str = "96gYZGLnJYVFmbjzopPSU6QiEV5fGqZNyN9nmNhvrZU5";

    pub fn json() -> String {
        format!(
            r#"{{"version":1,"fee_wallet":"{FEE_WALLET}","fee_bps":100,"jito_tip_accounts":["{TIP}"],
            "max_priority_lamports":100000000,"max_tip_lamports":100000000,
            "instructions":[
              {{"name":"pump.buy_exact_sol_in","program":"{PUMP}","discriminator":"38fc74089edfcd5f","kind":"buy","user_index":6,"sol_offset":8,"token_accounts":[[5,2,8]]}},
              {{"name":"pump.sell","program":"{PUMP}","discriminator":"33e685a4017f83ad","kind":"sell","user_index":6,"sol_offset":16,"token_accounts":[[5,2,9]]}}
            ]}}"#
        )
    }

    pub fn authority() -> SigningKey {
        SigningKey::from_bytes(&[42; 32])
    }

    pub fn rules() -> Rules {
        let j = json();
        let sig = authority().sign(j.as_bytes()).to_bytes();
        Rules::load(j.as_bytes(), &sig, &authority().verifying_key())
            .unwrap_or_else(|e| panic!("{e:?}"))
    }

    /// Construit un message legacy (format exact de Solana) à partir d'instructions.
    pub fn message(payer: Pubkey, signers: u8, ixs: &[(Pubkey, Vec<Pubkey>, Vec<u8>)]) -> Vec<u8> {
        let mut keys = vec![payer];
        for (p, accs, _) in ixs {
            for k in accs.iter().chain(std::iter::once(p)) {
                if !keys.contains(k) {
                    keys.push(*k);
                }
            }
        }
        let idx = |k: &Pubkey| keys.iter().position(|x| x == k).unwrap_or(0) as u8;
        let mut m = vec![signers, 0, 0, keys.len() as u8];
        for k in &keys {
            m.extend_from_slice(k);
        }
        m.extend_from_slice(&[7; 32]);
        m.push(ixs.len() as u8);
        for (p, accs, data) in ixs {
            m.push(idx(p));
            m.push(accs.len() as u8);
            m.extend(accs.iter().map(&idx));
            m.push(data.len() as u8);
            m.extend_from_slice(data);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use ed25519_dalek::Signer as _;
    use scope_solana::parse_message;

    const W: Pubkey = [0xaa; 32];

    fn k(s: &str) -> Pubkey {
        solana::pubkey(s).unwrap_or([0; 32])
    }

    const MINT: Pubkey = [0x5e; 32];

    /// Compte de tokens associé de `owner` pour MINT (programme de token classique).
    fn ata(owner: &Pubkey) -> Pubkey {
        solana::associated_token_address(owner, &MINT, &k(solana::TOKEN_PROGRAM)).unwrap_or([0; 32])
    }

    fn pump_buy(user: Pubkey, sol: u64) -> (Pubkey, Vec<Pubkey>, Vec<u8>) {
        let mut accs = vec![[1; 32]; 16];
        accs[2] = MINT;
        accs[5] = ata(&user);
        accs[6] = user;
        accs[8] = k(solana::TOKEN_PROGRAM);
        let mut data = vec![0x38, 0xfc, 0x74, 0x08, 0x9e, 0xdf, 0xcd, 0x5f];
        data.extend_from_slice(&sol.to_le_bytes());
        data.extend_from_slice(&1u64.to_le_bytes());
        (k(PUMP), accs, data)
    }

    fn pump_sell(user: Pubkey, tokens: u64, min_out: u64) -> (Pubkey, Vec<Pubkey>, Vec<u8>) {
        let mut accs = vec![[1; 32]; 16];
        accs[2] = MINT;
        accs[5] = ata(&user);
        accs[6] = user;
        accs[9] = k(solana::TOKEN_PROGRAM);
        let mut data = vec![0x33, 0xe6, 0x85, 0xa4, 0x01, 0x7f, 0x83, 0xad];
        data.extend_from_slice(&tokens.to_le_bytes());
        data.extend_from_slice(&min_out.to_le_bytes());
        (k(PUMP), accs, data)
    }

    fn transfer(from: Pubkey, to: Pubkey, lamports: u64) -> (Pubkey, Vec<Pubkey>, Vec<u8>) {
        let mut data = vec![2, 0, 0, 0];
        data.extend_from_slice(&lamports.to_le_bytes());
        (SYSTEM_PROGRAM, vec![from, to], data)
    }

    fn check(ixs: &[(Pubkey, Vec<Pubkey>, Vec<u8>)], out: u64) -> Result<TradeSummary, Violation> {
        let m = parse_message(&message(W, 1, ixs)).unwrap_or_else(|e| panic!("{e:?}"));
        rules().check_trade(&W, &m, out)
    }

    const ONE_SOL: u64 = 1_000_000_000;

    #[test]
    fn accepte_un_achat_avec_fee_exacte_et_tip() {
        let r = check(
            &[
                pump_buy(W, ONE_SOL),
                transfer(W, k(FEE_WALLET), ONE_SOL / 100),
                transfer(W, k(TIP), 100_000),
            ],
            0,
        );
        assert_eq!(
            r,
            Ok(TradeSummary {
                buy_lamports: ONE_SOL,
                sell_min_lamports: 0,
                fee: ONE_SOL / 100,
                tip: 100_000
            })
        );
    }

    #[test]
    fn refuse_une_fee_fausse() {
        for fee in [0, ONE_SOL / 100 - 1, ONE_SOL / 100 + 1, ONE_SOL / 10] {
            let r = check(&[pump_buy(W, ONE_SOL), transfer(W, k(FEE_WALLET), fee)], 0);
            assert!(
                matches!(r, Err(Violation::BadFee { .. })),
                "fee {fee} acceptée"
            );
        }
    }

    #[test]
    fn vente_fee_encadree_entre_minimum_garanti_et_attendu() {
        let sell = || pump_sell(W, 1_000, ONE_SOL / 2);
        assert!(
            check(
                &[sell(), transfer(W, k(FEE_WALLET), ONE_SOL / 200)],
                ONE_SOL
            )
            .is_ok()
        ); // 1 % du minimum
        assert!(
            check(
                &[sell(), transfer(W, k(FEE_WALLET), ONE_SOL / 100)],
                ONE_SOL
            )
            .is_ok()
        ); // 1 % de l'attendu
        assert!(check(&[sell(), transfer(W, k(FEE_WALLET), ONE_SOL / 50)], ONE_SOL).is_err()); // au-delà
        assert!(check(&[sell(), transfer(W, k(FEE_WALLET), 1)], ONE_SOL).is_err()); // en dessous
    }

    #[test]
    fn plafonne_la_priorite_et_le_tip_des_trades() {
        let fee = || transfer(W, k(FEE_WALLET), ONE_SOL / 100);
        let budget = |limit: u32, price: u64| {
            let cb = k(COMPUTE_BUDGET);
            let mut l = vec![2];
            l.extend_from_slice(&limit.to_le_bytes());
            let mut p = vec![3];
            p.extend_from_slice(&price.to_le_bytes());
            [(cb, vec![], l), (cb, vec![], p)]
        };
        // 250 000 CU × 400 000 000 µlamports = 0,1 SOL : pile au plafond, accepté.
        let [l, p] = budget(250_000, 400_000_000);
        assert!(check(&[l, p, pump_buy(W, ONE_SOL), fee()], 0).is_ok());
        // Un cran au-dessus : refusé.
        let [l, p] = budget(250_000, 400_000_004);
        assert!(matches!(
            check(&[l, p, pump_buy(W, ONE_SOL), fee()], 0),
            Err(Violation::PriorityTooHigh(_))
        ));
        // Tip : 0,1 SOL accepté, au-delà refusé (même réparti sur plusieurs transferts).
        assert!(
            check(
                &[
                    pump_buy(W, ONE_SOL),
                    fee(),
                    transfer(W, k(TIP), ONE_SOL / 10)
                ],
                0
            )
            .is_ok()
        );
        assert!(matches!(
            check(
                &[
                    pump_buy(W, ONE_SOL),
                    fee(),
                    transfer(W, k(TIP), ONE_SOL / 10),
                    transfer(W, k(TIP), 1)
                ],
                0
            ),
            Err(Violation::TipTooHigh(_))
        ));
    }

    #[test]
    fn refuse_tout_transfert_vers_une_autre_adresse() {
        let thief = [0x66; 32];
        assert_eq!(
            check(
                &[
                    pump_buy(W, ONE_SOL),
                    transfer(W, k(FEE_WALLET), ONE_SOL / 100),
                    transfer(W, thief, 1)
                ],
                0
            ),
            Err(Violation::TransferNotAllowed)
        );
    }

    #[test]
    fn refuse_un_achat_pour_le_compte_d_un_autre() {
        let r = check(
            &[
                pump_buy([0x66; 32], ONE_SOL),
                transfer(W, k(FEE_WALLET), ONE_SOL / 100),
            ],
            0,
        );
        assert!(matches!(r, Err(Violation::WrongUser(_))));
    }

    #[test]
    fn refuse_des_tokens_livres_ou_pris_sur_un_autre_compte() {
        let fee = || transfer(W, k(FEE_WALLET), ONE_SOL / 100);
        let thief = [0x66; 32];
        // Achat dont les tokens partent sur le compte d'un autre.
        let mut buy = pump_buy(W, ONE_SOL);
        buy.1[5] = ata(&thief);
        assert!(matches!(
            check(&[buy, fee()], 0),
            Err(Violation::ForeignTokenAccount(_))
        ));
        // Faux « programme de token » pour fabriquer une adresse dérivée qui colle.
        let mut fake = pump_buy(W, ONE_SOL);
        fake.1[8] = [0x77; 32];
        fake.1[5] = solana::associated_token_address(&W, &MINT, &[0x77; 32]).unwrap_or([0; 32]);
        assert!(matches!(
            check(&[fake, fee()], 0),
            Err(Violation::ForeignTokenAccount(_))
        ));
        // Vente depuis un compte qui n'est pas celui du wallet.
        let mut sell = pump_sell(W, 1_000, ONE_SOL / 2);
        sell.1[5] = [0x44; 32];
        assert!(matches!(
            check(&[sell, transfer(W, k(FEE_WALLET), ONE_SOL / 100)], ONE_SOL),
            Err(Violation::ForeignTokenAccount(_))
        ));
    }

    #[test]
    fn refuse_les_programmes_et_instructions_dangereux() {
        let fee = || transfer(W, k(FEE_WALLET), ONE_SOL / 100);
        let unknown = ([0x77; 32], vec![W], vec![1, 2, 3]);
        assert!(matches!(
            check(&[pump_buy(W, ONE_SOL), fee(), unknown], 0),
            Err(Violation::ProgramNotAllowed(_))
        ));
        // System Assign (1) : donnerait le wallet à un autre programme.
        let assign = (
            SYSTEM_PROGRAM,
            vec![W],
            [vec![1, 0, 0, 0], vec![0x66; 32]].concat(),
        );
        assert!(check(&[pump_buy(W, ONE_SOL), fee(), assign], 0).is_err());
        // Token Approve (4) et SetAuthority (6) : donneraient le contrôle des tokens.
        for op in [4u8, 6] {
            let tok = (
                k(solana::TOKEN_PROGRAM),
                vec![[1; 32], [0x66; 32], W],
                vec![op, 1, 0, 0, 0, 0, 0, 0, 0],
            );
            assert!(
                check(&[pump_buy(W, ONE_SOL), fee(), tok], 0).is_err(),
                "token op {op} acceptée"
            );
        }
        // Instruction pump.fun inconnue des règles (autre discriminateur).
        let other = (k(PUMP), vec![W; 16], vec![9; 24]);
        assert!(check(&[other, fee()], 0).is_err());
    }

    #[test]
    fn refuse_plusieurs_signataires_et_un_autre_payeur() {
        let ixs = [
            pump_buy(W, ONE_SOL),
            transfer(W, k(FEE_WALLET), ONE_SOL / 100),
        ];
        let two = parse_message(&message(W, 2, &ixs)).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            rules().check_trade(&W, &two, 0),
            Err(Violation::NotSoleSigner)
        );
        let other_payer =
            parse_message(&message([0x66; 32], 1, &ixs)).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            rules().check_trade(&W, &other_payer, 0),
            Err(Violation::WrongFeePayer)
        );
    }

    #[test]
    fn refuse_une_transaction_sans_trade() {
        assert_eq!(check(&[transfer(W, k(TIP), 1)], 0), Err(Violation::NoTrade));
    }

    #[test]
    fn recuperation_du_loyer_fermetures_seules() {
        let acc = |b: u8| [b; 32];
        let close =
            |a: [u8; 32], dest: [u8; 32]| (k(solana::TOKEN_PROGRAM), vec![a, dest, W], vec![9]);
        // Fermer des comptes vers le wallet lui-même, sans rien d'autre : accepté.
        let r = check(&[close(acc(0x41), W), close(acc(0x42), W)], 0);
        assert!(r.is_ok(), "{r:?}");
        // Avec un tip ou une fee : refusé (aucun SOL ne doit partir sans trade).
        assert_eq!(
            check(&[close(acc(0x41), W), transfer(W, k(TIP), 1)], 0),
            Err(Violation::NoTrade)
        );
        assert_eq!(
            check(&[close(acc(0x41), W), transfer(W, k(FEE_WALLET), 1)], 0),
            Err(Violation::NoTrade)
        );
        // Le loyer vers quelqu'un d'autre : refusé.
        assert!(check(&[close(acc(0x41), [0x66; 32])], 0).is_err());
    }

    #[test]
    fn autorise_wrap_unwrap_sur_son_propre_compte_wsol() {
        let ata =
            solana::associated_token_address(&W, &k(solana::WSOL_MINT), &k(solana::TOKEN_PROGRAM))
                .unwrap_or([0; 32]);
        let sync = (k(solana::TOKEN_PROGRAM), vec![ata], vec![17]);
        let close = (k(solana::TOKEN_PROGRAM), vec![ata, W, W], vec![9]);
        let r = check(
            &[
                transfer(W, ata, ONE_SOL),
                sync,
                pump_buy(W, ONE_SOL),
                transfer(W, k(FEE_WALLET), ONE_SOL / 100),
                close,
            ],
            0,
        );
        assert!(r.is_ok(), "{r:?}");
        // Close vers un autre destinataire : refusé.
        let steal = (k(solana::TOKEN_PROGRAM), vec![ata, [0x66; 32], W], vec![9]);
        assert!(
            check(
                &[
                    pump_buy(W, ONE_SOL),
                    transfer(W, k(FEE_WALLET), ONE_SOL / 100),
                    steal
                ],
                0
            )
            .is_err()
        );
    }

    /// Les VRAIES règles (`infra/rules/rules.json`), signées par la clé de test.
    fn real_rules() -> Rules {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../infra/rules/rules.json");
        let j = std::fs::read(path).unwrap_or_default();
        let sig = authority().sign(&j).to_bytes();
        Rules::load(&j, &sig, &authority().verifying_key()).unwrap_or_else(|e| panic!("{e:?}"))
    }

    /// Transaction complète comme le moteur la construit : budget de calcul + trade + fee + tip.
    fn engine_tx(wallet: &Pubkey, mut trade: Vec<solana::Ix>, fee: u64) -> Message {
        let rules = real_rules();
        let mut ixs = vec![
            solana::set_compute_unit_limit(250_000).unwrap_or_else(|| panic!("cu")),
            solana::set_compute_unit_price(100_000).unwrap_or_else(|| panic!("prix")),
        ];
        ixs.append(&mut trade);
        ixs.push(solana::transfer(wallet, &rules.fee_wallet, fee));
        ixs.push(solana::transfer(
            wallet,
            rules.tips.iter().next().unwrap_or(&[0; 32]),
            10_000,
        ));
        let msg =
            solana::compile_legacy(wallet, &ixs, &[9; 32]).unwrap_or_else(|e| panic!("{e:?}"));
        parse_message(&msg).unwrap_or_else(|e| panic!("{e:?}"))
    }

    fn fixtures(sub: &str) -> Vec<serde_json::Value> {
        let dir = format!(
            "{}/../pump/tests/fixtures/{sub}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_dir(dir)
            .map(|d| {
                d.filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|x| x == "json"))
                    .filter_map(|p| serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn b64(v: &serde_json::Value) -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(v.as_str().unwrap_or_default())
            .unwrap_or_default()
    }

    #[test]
    fn les_trades_pumpswap_du_moteur_passent_les_vraies_regles() {
        use scope_pump::amm::{GlobalConfig, Pool, Swap};
        let pools = fixtures("amm");
        assert!(pools.len() >= 2);
        for fx in &pools {
            let config = GlobalConfig::decode(&b64(&fx["accounts"]["global_config"]["data"]))
                .unwrap_or_else(|e| panic!("{e:?}"));
            let pool = Pool::decode(&b64(&fx["accounts"]["pool"]["data"]))
                .unwrap_or_else(|e| panic!("{e:?}"));
            let swap = Swap {
                config: &config,
                pool: &pool,
                pool_key: k(fx["pool"].as_str().unwrap_or_default()),
                base_token_program: k(fx["base_token_program"].as_str().unwrap_or_default()),
                user: W,
                fee_recipient_index: 3,
                buyback_index: 5,
            };
            let ok = |r: Result<solana::Ix, scope_pump::PumpError>| {
                r.unwrap_or_else(|e| panic!("{e:?}"))
            };
            // Achat : WSOL ouvert, compte du coin, achat exact, WSOL refermé ; fee exacte.
            let mut buy = swap.open_wsol(ONE_SOL).unwrap_or_else(|e| panic!("{e:?}"));
            buy.extend([
                ok(swap.create_base_ata()),
                ok(swap.buy_exact_quote_in(ONE_SOL, 1)),
                ok(swap.close_wsol()),
            ]);
            let r = real_rules().check_trade(&W, &engine_tx(&W, buy.clone(), ONE_SOL / 100), 0);
            assert!(r.is_ok(), "achat refusé : {r:?}");
            // Vente totale : WSOL ouvert, vente, WSOL refermé, compte du coin refermé ; fee encadrée.
            let sell = vec![
                swap.open_wsol(0).unwrap_or_default().remove(0),
                ok(swap.sell(1_000, ONE_SOL / 2)),
                ok(swap.close_wsol()),
                ok(swap.close_base_ata()),
            ];
            let r =
                real_rules().check_trade(&W, &engine_tx(&W, sell.clone(), ONE_SOL / 100), ONE_SOL);
            assert!(r.is_ok(), "vente refusée : {r:?}");

            // Moteur compromis : tokens achetés livrés sur le compte d'un autre → refusé.
            let thief = [0x66; 32];
            let mut evil = buy.clone();
            let i = evil
                .iter()
                .position(|ix| ix.data.starts_with(&[0xc6, 0x2e]))
                .unwrap_or(0);
            evil[i].accounts[5].pubkey =
                solana::associated_token_address(&thief, &pool.base_mint, &swap.base_token_program)
                    .unwrap_or([0; 32]);
            assert!(matches!(
                real_rules().check_trade(&W, &engine_tx(&W, evil, ONE_SOL / 100), 0),
                Err(Violation::ForeignTokenAccount(_))
            ));
            // … ou SOL d'une vente versé sur le compte WSOL d'un autre → refusé.
            let mut evil = sell.clone();
            evil[1].accounts[6].pubkey = solana::associated_token_address(
                &thief,
                &k(solana::WSOL_MINT),
                &k(solana::TOKEN_PROGRAM),
            )
            .unwrap_or([0; 32]);
            assert!(matches!(
                real_rules().check_trade(&W, &engine_tx(&W, evil, ONE_SOL / 100), ONE_SOL),
                Err(Violation::ForeignTokenAccount(_))
            ));
        }
    }

    #[test]
    fn les_trades_courbe_du_moteur_passent_les_vraies_regles() {
        use scope_pump::{BondingCurve, Global, Trade};
        let coins = fixtures("");
        assert!(coins.len() >= 2);
        for fx in &coins {
            let global = Global::decode(&b64(&fx["accounts"]["global"]["data"]))
                .unwrap_or_else(|e| panic!("{e:?}"));
            let curve = BondingCurve::decode(&b64(&fx["accounts"]["bonding_curve"]["data"]))
                .unwrap_or_else(|e| panic!("{e:?}"));
            let trade = Trade {
                global: &global,
                curve: &curve,
                mint: k(fx["mint"].as_str().unwrap_or_default()),
                token_program: k(fx["token_program"].as_str().unwrap_or_default()),
                user: W,
                fee_recipient_index: 2,
                buyback_index: 6,
            };
            let ok = |r: Result<solana::Ix, scope_pump::PumpError>| {
                r.unwrap_or_else(|e| panic!("{e:?}"))
            };
            let buy = vec![
                ok(trade.create_user_ata()),
                ok(trade.buy_exact_sol_in(ONE_SOL, 1)),
            ];
            let r = real_rules().check_trade(&W, &engine_tx(&W, buy.clone(), ONE_SOL / 100), 0);
            assert!(r.is_ok(), "achat refusé : {r:?}");
            let sell = vec![
                ok(trade.sell(1_000, ONE_SOL / 2)),
                ok(trade.close_user_ata()),
            ];
            let r = real_rules().check_trade(&W, &engine_tx(&W, sell, ONE_SOL / 100), ONE_SOL);
            assert!(r.is_ok(), "vente refusée : {r:?}");
            let mut evil = buy;
            evil[1].accounts[5].pubkey = [0x66; 32];
            assert!(matches!(
                real_rules().check_trade(&W, &engine_tx(&W, evil, ONE_SOL / 100), 0),
                Err(Violation::ForeignTokenAccount(_))
            ));
        }
    }

    #[test]
    fn recuperation_des_compteurs_pump_sans_fee_et_seulement_vers_le_wallet() {
        use scope_pump::volume::{Market, UserVolume, reclaim};
        let with_cashback = UserVolume {
            cashback_earned: 500,
            ..UserVolume::default()
        };
        for market in [Market::Curve, Market::PumpSwap] {
            for v in [UserVolume::default(), with_cashback.clone()] {
                let ixs = reclaim(market, &W, &v, false).unwrap_or_else(|e| panic!("{e:?}"));
                // Entretien : aucune fee Scope (0), accepté.
                let r = real_rules().check_trade(&W, &engine_tx(&W, ixs.clone(), 0), 0);
                assert!(r.is_ok(), "{market:?} refusé : {r:?}");
                // Une fee prélevée sur un entretien : refusée.
                assert!(matches!(
                    real_rules().check_trade(&W, &engine_tx(&W, ixs.clone(), 1), 0),
                    Err(Violation::BadFee { .. })
                ));
                // Dépôt ou cashback détourné vers un autre wallet : refusé.
                let mut evil = ixs.clone();
                let last = evil.len() - 1;
                evil[last].accounts[0].pubkey = [0x66; 32];
                assert!(
                    real_rules()
                        .check_trade(&W, &engine_tx(&W, evil, 0), 0)
                        .is_err()
                );
            }
        }
        // Cashback PumpSwap versé sur le compte WSOL d'un autre : refusé.
        let mut ixs = reclaim(Market::PumpSwap, &W, &with_cashback, false).unwrap_or_default();
        let claim = ixs
            .iter()
            .position(|i| i.data.starts_with(&[0x25, 0x3a]))
            .unwrap_or(0);
        ixs[claim].accounts[5].pubkey = solana::associated_token_address(
            &[0x66; 32],
            &k(solana::WSOL_MINT),
            &k(solana::TOKEN_PROGRAM),
        )
        .unwrap_or([0; 32]);
        assert!(matches!(
            real_rules().check_trade(&W, &engine_tx(&W, ixs, 0), 0),
            Err(Violation::ForeignTokenAccount(_))
        ));
    }

    /// REJEU : de vrais lancements enregistrés (tests/fixtures/launches) passent dans le pipeline du snipe
    /// (décodage → état du coin sans réseau → achat construit) puis dans les VRAIES règles du signer.
    #[test]
    fn rejeu_de_vrais_lancements_dans_le_pipeline_et_le_signer() {
        use scope_pump::cu::Existing;
        use scope_pump::events::decode_logs;
        use scope_pump::{BondingCurve, Global, Trade, with_slippage};
        let dir = format!("{}/../pump/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
        let sample =
            std::fs::read_to_string(format!("{dir}/launches/sample.jsonl")).unwrap_or_default();
        // Compte global pump.fun réel (capturé avec les coins de la courbe).
        let any_coin = fixtures("").into_iter().next().unwrap_or_default();
        let global = Global::decode(&b64(&any_coin["accounts"]["global"]["data"]))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let (mut sniped, mut skipped) = (0, 0);
        for line in sample.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
            let logs: Vec<String> = v["logs"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|l| l.as_str().map(String::from))
                .collect();
            let events = decode_logs(&logs);
            let curve = BondingCurve::from_events(&events)
                .unwrap_or_else(|| panic!("création non décodée : {}", v["mint"]));
            let Some(scope_pump::events::Event::Create(c)) = events
                .into_iter()
                .find(|e| matches!(e, scope_pump::events::Event::Create(_)))
            else {
                panic!("pas de création");
            };
            assert_eq!(
                solana::bs58_encode(&c.mint),
                v["mint"].as_str().unwrap_or_default()
            );
            // Même décision que le pipeline : coins non cotés en SOL et Mayhem ignorés.
            if !curve.is_sol_quoted() || curve.is_mayhem_mode {
                skipped += 1;
                continue;
            }
            let t = Trade {
                global: &global,
                curve: &curve,
                mint: c.mint,
                token_program: c.token_program,
                user: W,
                fee_recipient_index: 0,
                buyback_index: 0,
            };
            let sol = 10_000_000;
            let min = with_slippage(curve.estimate_tokens_out(sol), 2_000).max(1);
            assert!(min > 1, "estimation nulle : {}", v["mint"]);
            let ixs = vec![
                t.create_user_ata().unwrap_or_else(|e| panic!("{e:?}")),
                t.buy_exact_sol_in(sol, min)
                    .unwrap_or_else(|e| panic!("{e:?}")),
            ];
            let cu = t
                .buy_compute_units(&Existing::default())
                .unwrap_or_else(|e| panic!("{e:?}"));
            assert!(
                (80_000..200_000).contains(&cu),
                "limite de calcul inattendue : {cu}"
            );
            let r = real_rules().check_trade(&W, &engine_tx(&W, ixs, sol / 100), 0);
            assert!(
                r.is_ok(),
                "achat refusé par le signer : {r:?} ({})",
                v["mint"]
            );
            sniped += 1;
        }
        // Décisions figées sur cet échantillon : toute modification qui les change doit être voulue.
        assert_eq!((sniped, skipped), (17, 6), "décisions du rejeu modifiées");
    }

    #[test]
    fn rechargement_a_chaud_seulement_si_la_signature_est_valide()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("rules.json");
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let write = |json: &str, signer: &ed25519_dalek::SigningKey| -> std::io::Result<()> {
            std::fs::write(&path, json)?;
            std::fs::write(
                dir.path().join("rules.json.sig"),
                hex(&signer.sign(json.as_bytes()).to_bytes()),
            )
        };
        let store = RulesStore::new(path.clone(), authority().verifying_key());
        write(&json(), &authority())?;
        assert_eq!(store.reload_if_changed(), Some(Ok(1)));
        assert_eq!(store.reload_if_changed(), None); // rien de nouveau
        // Un pirate réécrit le fichier (fee détournée) sans la clé d'autorité : refusé, règles inchangées.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let evil = json()
            .replace("\"version\":1", "\"version\":2")
            .replace(FEE_WALLET, TIP);
        write(&evil, &ed25519_dalek::SigningKey::from_bytes(&[13; 32]))?;
        assert_eq!(
            store.reload_if_changed(),
            Some(Err(RulesError::BadSignature))
        );
        assert_eq!(store.with(|r| r.version), Some(1));
        // Nouvelle version correctement signée : appliquée.
        std::thread::sleep(std::time::Duration::from_millis(20));
        write(
            &json().replace("\"version\":1", "\"version\":2"),
            &authority(),
        )?;
        assert_eq!(store.reload_if_changed(), Some(Ok(2)));
        Ok(())
    }

    #[test]
    fn refuse_un_fichier_de_regles_mal_signe_ou_invalide() {
        let j = json();
        let other = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let bad_sig = other.sign(j.as_bytes()).to_bytes();
        assert_eq!(
            Rules::load(j.as_bytes(), &bad_sig, &authority().verifying_key()).err(),
            Some(RulesError::BadSignature)
        );
        // Fichier modifié après signature.
        let sig = authority().sign(j.as_bytes()).to_bytes();
        let tampered = j.replace("\"fee_bps\":100", "\"fee_bps\":999");
        assert_eq!(
            Rules::load(tampered.as_bytes(), &sig, &authority().verifying_key()).err(),
            Some(RulesError::BadSignature)
        );
        // Bien signé mais fee absurde : refusé quand même.
        let crazy = j.replace("\"fee_bps\":100", "\"fee_bps\":5000");
        let s2 = authority().sign(crazy.as_bytes()).to_bytes();
        assert!(matches!(
            Rules::load(crazy.as_bytes(), &s2, &authority().verifying_key()),
            Err(RulesError::BadFile(_))
        ));
    }
}
