//! Limite de calcul EXACTE de chaque trade, calculée sans aucun appel réseau.
//!
//! Sur Solana, la priorité se paie sur la limite RÉSERVÉE (pas sur la consommation) et une transaction
//! qui dépasse sa limite échoue. On calcule donc ce que le trade va consommer, coin par coin :
//! - chaque programme recalcule certaines adresses : ~1 500 unités par essai, et le nombre d'essais se
//!   déduit hors ligne du « bump » de chaque adresse (255 = trouvé du premier coup) ;
//! - créer un compte de tokens coûte une base fixe + ses propres essais ; s'il existe déjà, beaucoup moins.
//!
//! Constantes mesurées sur mainnet le 03/10/2026 (`tools/pump-oracle/src/measure-cu.ts`, simulations
//! instruction par instruction sur des dizaines de coins frais) : base = écart résiduel MAXIMUM observé.
//! Le canari quotidien vérifie que la consommation réelle reste sous ces limites.

use scope_solana::{Pubkey, find_program_address_bump};

use crate::amm::{AMM_PROGRAM, Swap, TOKEN_PROGRAM};
use crate::{ATA_PROGRAM, FEE_PROGRAM, PUMP_PROGRAM, PumpError, Trade, WSOL_MINT, key};

/// Coût d'un essai de recherche d'adresse (create_program_address).
const PER_STEP: u32 = 1_500;
/// Instructions de pump.fun (courbe) / PumpSwap, hors recherches d'adresses modélisées.
const CURVE_BUY: u32 = 64_900;
const CURVE_SELL: u32 = 48_600;
const AMM_BUY: u32 = 79_500;
const AMM_SELL: u32 = 70_200;
/// Création du compte de volume pump.fun (premier achat d'un wallet sur ce programme).
const VOLUME_ACCUMULATOR_CREATE: u32 = 3_500;
/// Création d'un compte de tokens (hors essais) : Token-2022 / Token classique / déjà existant.
const ATA_CREATE_2022: u32 = 17_200;
const ATA_CREATE_TOKEN: u32 = 13_500;
const ATA_EXISTING: u32 = 4_400;
/// Instructions simples : budget de calcul, transferts, SyncNative, fermetures de comptes.
const SIMPLE: u32 = 200;
const CLOSE_ACCOUNT: u32 = 2_000;
/// Marge : 5 % + 2 000 (cas non mesurés : coins cashback, Token classique, Mayhem).
const MARGIN_PCT: u32 = 5;
const MARGIN_FIXED: u32 = 2_000;

/// Ce qui existe déjà on-chain pour ce wallet (le moteur le sait sans appel au moment d'un snipe).
#[derive(Clone, Copy, Debug, Default)]
pub struct Existing {
    pub user_tokens: bool,
    pub user_wsol: bool,
    pub volume_accumulator: bool,
}

fn steps(seeds: &[&[u8]], program: &str) -> Result<u32, PumpError> {
    let (_, bump) = find_program_address_bump(seeds, &key(program)?).ok_or(PumpError::NoPda)?;
    Ok(u32::from(255 - bump) * PER_STEP)
}

fn ata_steps(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Result<u32, PumpError> {
    steps(&[owner, token_program, mint], ATA_PROGRAM)
}

/// Création idempotente d'un compte de tokens : coût exact selon le programme, le bump et l'existence.
fn ata_create(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
    exists: bool,
) -> Result<u32, PumpError> {
    let base = if exists {
        ATA_EXISTING
    } else if *token_program == key(TOKEN_PROGRAM)? {
        ATA_CREATE_TOKEN
    } else {
        ATA_CREATE_2022
    };
    Ok(base + ata_steps(owner, mint, token_program)?)
}

/// Ajoute la marge et les instructions communes (budget ×2, fee Scope, tip).
fn finish(core: u32) -> u32 {
    let total = core + 4 * SIMPLE;
    total + total * MARGIN_PCT / 100 + MARGIN_FIXED
}

impl Trade<'_> {
    /// Adresses que pump.fun recalcule (courbe, son compte de tokens, coffre du créateur, courbe v2, compteur).
    fn curve_steps(&self) -> Result<u32, PumpError> {
        let curve = scope_solana::find_program_address(
            &[b"bonding-curve", &self.mint],
            &key(PUMP_PROGRAM)?,
        )
        .ok_or(PumpError::NoPda)?;
        Ok(steps(&[b"bonding-curve", &self.mint], PUMP_PROGRAM)?
            + ata_steps(&curve, &self.mint, &self.token_program)?
            + steps(&[b"creator-vault", &self.curve.creator], PUMP_PROGRAM)?
            + steps(&[b"bonding-curve-v2", &self.mint], PUMP_PROGRAM)?
            + steps(&[b"user_volume_accumulator", &self.user], PUMP_PROGRAM)?
            + steps(&[b"fee_config", &key(PUMP_PROGRAM)?], FEE_PROGRAM)?)
    }

    /// Limite exacte de l'achat (compte de tokens créé si besoin + achat).
    pub fn buy_compute_units(&self, e: &Existing) -> Result<u32, PumpError> {
        let mut core = ata_create(&self.user, &self.mint, &self.token_program, e.user_tokens)?
            + CURVE_BUY
            + self.curve_steps()?;
        if !e.volume_accumulator {
            core += VOLUME_ACCUMULATOR_CREATE;
        }
        Ok(finish(core))
    }

    /// Limite exacte de la vente (+ fermeture du compte de tokens si vente totale).
    pub fn sell_compute_units(&self, close: bool) -> Result<u32, PumpError> {
        let core = CURVE_SELL + self.curve_steps()? + if close { CLOSE_ACCOUNT } else { 0 };
        Ok(finish(core))
    }
}

impl Swap<'_> {
    /// Adresses que PumpSwap recalcule (coffre du créateur et son compte WSOL, pool v2, compte du coin
    /// de l'utilisateur, compteur).
    fn amm_steps(&self) -> Result<u32, PumpError> {
        let (wsol, token) = (key(WSOL_MINT)?, key(TOKEN_PROGRAM)?);
        let vault = scope_solana::find_program_address(
            &[b"creator_vault", &self.pool.coin_creator],
            &key(AMM_PROGRAM)?,
        )
        .ok_or(PumpError::NoPda)?;
        Ok(
            steps(&[b"creator_vault", &self.pool.coin_creator], AMM_PROGRAM)?
                + ata_steps(&vault, &wsol, &token)?
                + steps(&[b"pool-v2", &self.pool.base_mint], AMM_PROGRAM)?
                + ata_steps(&self.user, &self.pool.base_mint, &self.base_token_program)?
                + steps(&[b"user_volume_accumulator", &self.user], AMM_PROGRAM)?,
        )
    }

    fn wsol_open(&self, e: &Existing, funded: bool) -> Result<u32, PumpError> {
        let (wsol, token) = (key(WSOL_MINT)?, key(TOKEN_PROGRAM)?);
        Ok(ata_create(&self.user, &wsol, &token, e.user_wsol)?
            + if funded { 2 * SIMPLE } else { 0 })
    }

    /// Limite exacte de l'achat : WSOL ouvert et approvisionné, compte du coin, achat, WSOL refermé.
    pub fn buy_compute_units(&self, e: &Existing) -> Result<u32, PumpError> {
        let mut core = self.wsol_open(e, true)?
            + ata_create(
                &self.user,
                &self.pool.base_mint,
                &self.base_token_program,
                e.user_tokens,
            )?
            + AMM_BUY
            + self.amm_steps()?
            + CLOSE_ACCOUNT;
        if !e.volume_accumulator {
            core += VOLUME_ACCUMULATOR_CREATE;
        }
        Ok(finish(core))
    }

    /// Limite exacte de la vente : WSOL ouvert, vente, WSOL refermé (+ compte du coin si vente totale).
    pub fn sell_compute_units(&self, e: &Existing, close: bool) -> Result<u32, PumpError> {
        let core = self.wsol_open(e, false)?
            + AMM_SELL
            + self.amm_steps()?
            + CLOSE_ACCOUNT
            + if close { CLOSE_ACCOUNT } else { 0 };
        Ok(finish(core))
    }
}
