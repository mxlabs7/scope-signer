//! Événements que pump.fun publie dans les logs de ses transactions (« Program data: <base64> », format
//! Anchor : discriminateur de 8 octets + champs Borsh). Décodés en local, en quelques microsecondes.
//!
//! - `CreateEvent` : un coin est créé (créateur, mint, courbe, réserves initiales, options).
//! - `TradeEvent` : un achat ou une vente (dont l'achat du créateur au lancement, « dev buy »).
//! - `AmmBuyEvent` : un achat sur PumpSwap (coin migré), publié de la même façon par le programme AMM.
//!
//! Format vérifié sur de vrais messages reçus par WebSocket (tests/fixtures/events). Les champs ajoutés
//! en fin d'événement par pump.fun au fil du temps valent 0 / faux / vide s'ils sont absents.

use base64::Engine as _;
use scope_solana::Pubkey;

use crate::{Cursor, PumpError};

const CREATE: [u8; 8] = [0x1b, 0x72, 0xa9, 0x4d, 0xde, 0xeb, 0x63, 0x76];
const TRADE: [u8; 8] = [0xbd, 0xdb, 0x7f, 0xd3, 0x4e, 0xe6, 0x61, 0xee];
const AMM_BUY: [u8; 8] = [103, 244, 82, 31, 44, 245, 119, 119];
const AMM_SELL: [u8; 8] = [62, 47, 55, 10, 165, 3, 220, 42];
/// Garde-fou : un nom, symbole ou lien plus long est forcément une donnée corrompue.
const MAX_STRING: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CreateEvent {
    pub name: String,
    pub symbol: String,
    pub uri: String,
    pub mint: Pubkey,
    pub bonding_curve: Pubkey,
    /// Wallet qui a envoyé la transaction de création.
    pub user: Pubkey,
    /// Créateur enregistré du coin (reçoit les fees créateur).
    pub creator: Pubkey,
    pub timestamp: i64,
    pub virtual_token_reserves: u64,
    pub virtual_sol_reserves: u64,
    pub real_token_reserves: u64,
    pub token_total_supply: u64,
    pub token_program: Pubkey,
    pub is_mayhem_mode: bool,
    pub is_cashback_enabled: bool,
    pub quote_mint: Pubkey,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TradeEvent {
    pub mint: Pubkey,
    pub sol_amount: u64,
    pub token_amount: u64,
    pub is_buy: bool,
    pub user: Pubkey,
    pub timestamp: i64,
    pub virtual_sol_reserves: u64,
    pub virtual_token_reserves: u64,
    pub real_sol_reserves: u64,
    pub real_token_reserves: u64,
    pub creator: Pubkey,
    /// Instruction d'origine (« buy », « buy_exact_sol_in », « sell »…), si publiée.
    pub ix_name: String,
    pub is_mayhem_mode: bool,
    /// Mint de cotation (vide ou WSOL = SOL), si publié.
    pub quote_mint: Pubkey,
    /// Part cashback prélevée : non nulle seulement sur un coin cashback.
    pub cashback_fee_basis_points: u64,
}

/// Achat sur PumpSwap. Le mint n'y figure pas : il se retrouve par le pool.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmmBuyEvent {
    pub pool: Pubkey,
    pub user: Pubkey,
    /// SOL dépensé par l'acheteur (frais compris).
    pub user_quote_amount_in: u64,
    /// Réserves du pool AVANT l'achat.
    pub pool_base_token_reserves: u64,
    pub pool_quote_token_reserves: u64,
    pub base_amount_out: u64,
    pub quote_amount_in: u64,
    /// Frais LP : restent dans le pool (sa réserve de SOL augmente de `quote_amount_in + lp_fee`).
    pub lp_fee: u64,
    pub coin_creator: Pubkey,
    pub coin_creator_fee_basis_points: u64,
    pub ix_name: String,
    pub cashback_fee_basis_points: u64,
    pub virtual_quote_reserves: i128,
}

/// Vente sur PumpSwap (le mint n'y figure pas : il se retrouve par le pool).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AmmSellEvent {
    pub pool: Pubkey,
    pub user: Pubkey,
    pub base_amount_in: u64,
    /// Réserves du pool AVANT la vente.
    pub pool_base_token_reserves: u64,
    pub pool_quote_token_reserves: u64,
    /// SOL sorti du pool (vendeur + frais protocole et créateur ; les frais LP y restent).
    pub quote_amount_out_without_lp_fee: u64,
    pub coin_creator: Pubkey,
    pub cashback_fee_basis_points: u64,
    pub virtual_quote_reserves: i128,
}

impl AmmBuyEvent {
    /// Réserves RÉELLES du pool juste APRÈS l'achat : (tokens, SOL). Le SOL payé entre (frais LP
    /// compris, ils restent dans le pool), les tokens sortent. La réserve virtuelle est à part.
    pub fn reserves_after(&self) -> (u64, u64) {
        (
            self.pool_base_token_reserves
                .saturating_sub(self.base_amount_out),
            self.pool_quote_token_reserves
                .saturating_add(self.quote_amount_in)
                .saturating_add(self.lp_fee),
        )
    }
}

impl AmmSellEvent {
    /// Réserves RÉELLES du pool juste APRÈS la vente : (tokens, SOL). Les tokens entrent, le SOL sort
    /// (sauf les frais LP, qui restent dans le pool). La réserve virtuelle est à part.
    pub fn reserves_after(&self) -> (u64, u64) {
        (
            self.pool_base_token_reserves
                .saturating_add(self.base_amount_in),
            self.pool_quote_token_reserves
                .saturating_sub(self.quote_amount_out_without_lp_fee),
        )
    }
}

/// Événement pump.fun reconnu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Create(CreateEvent),
    Trade(TradeEvent),
    AmmBuy(AmmBuyEvent),
    AmmSell(AmmSellEvent),
}

impl Cursor<'_> {
    fn string(&mut self, w: &'static str) -> Result<String, PumpError> {
        let len = u32::from_le_bytes(
            self.take(4, w)?
                .try_into()
                .map_err(|_| PumpError::BadAccount(w))?,
        ) as usize;
        if len > MAX_STRING {
            return Err(PumpError::BadAccount(w));
        }
        Ok(String::from_utf8_lossy(self.take(len, w)?).into_owned())
    }

    fn i64(&mut self, w: &'static str) -> Result<i64, PumpError> {
        Ok(i64::from_le_bytes(
            self.take(8, w)?
                .try_into()
                .map_err(|_| PumpError::BadAccount(w))?,
        ))
    }

    /// Champ optionnel de fin d'événement : défaut s'il est absent.
    fn opt_key(&mut self, w: &'static str) -> Pubkey {
        self.key(w).unwrap_or([0; 32])
    }
    fn opt_bool(&mut self, w: &'static str) -> bool {
        self.bool(w).unwrap_or(false)
    }
}

fn create(data: &[u8]) -> Result<CreateEvent, PumpError> {
    let mut c = Cursor(data);
    let w = "CreateEvent";
    Ok(CreateEvent {
        name: c.string(w)?,
        symbol: c.string(w)?,
        uri: c.string(w)?,
        mint: c.key(w)?,
        bonding_curve: c.key(w)?,
        user: c.key(w)?,
        creator: c.key(w)?,
        timestamp: c.i64(w)?,
        virtual_token_reserves: c.u64(w)?,
        virtual_sol_reserves: c.u64(w)?,
        real_token_reserves: c.u64(w)?,
        token_total_supply: c.u64(w)?,
        token_program: c.opt_key(w),
        is_mayhem_mode: c.opt_bool(w),
        is_cashback_enabled: c.opt_bool(w),
        quote_mint: c.opt_key(w),
    })
}

fn trade(data: &[u8]) -> Result<TradeEvent, PumpError> {
    let mut c = Cursor(data);
    let w = "TradeEvent";
    let mint = c.key(w)?;
    let sol_amount = c.u64(w)?;
    let token_amount = c.u64(w)?;
    let is_buy = c.bool(w)?;
    let user = c.key(w)?;
    let timestamp = c.i64(w)?;
    let virtual_sol_reserves = c.u64(w)?;
    let virtual_token_reserves = c.u64(w)?;
    let real_sol_reserves = c.u64(w)?;
    let real_token_reserves = c.u64(w)?;
    c.key(w)?; // fee_recipient
    c.u64(w)?; // fee_basis_points
    c.u64(w)?; // fee
    let creator = c.opt_key(w);
    // Fin de l'événement (champs ajoutés au fil du temps) : lus si présents.
    let mut tail = || -> Result<(String, bool, u64, Pubkey), PumpError> {
        c.u64(w)?; // creator_fee_basis_points
        c.u64(w)?; // creator_fee
        c.bool(w)?; // track_volume
        for _ in 0..3 {
            c.u64(w)?; // total_unclaimed_tokens, total_claimed_tokens, current_sol_volume
        }
        c.i64(w)?; // last_update_timestamp
        let ix_name = c.string(w)?;
        let mayhem = c.bool(w)?;
        let cashback_bps = c.u64(w)?;
        for _ in 0..3 {
            c.u64(w)?; // cashback, buyback_fee_basis_points, buyback_fee
        }
        let holders = u32::from_le_bytes(
            c.take(4, w)?
                .try_into()
                .map_err(|_| PumpError::BadAccount(w))?,
        ) as usize;
        if holders > 64 {
            return Err(PumpError::BadAccount(w));
        }
        c.take(holders * 34, w)?; // shareholders (adresse + part)
        Ok((ix_name, mayhem, cashback_bps, c.key(w)?))
    };
    let (ix_name, is_mayhem_mode, cashback_fee_basis_points, quote_mint) =
        tail().unwrap_or_default();
    Ok(TradeEvent {
        mint,
        sol_amount,
        token_amount,
        is_buy,
        user,
        timestamp,
        virtual_sol_reserves,
        virtual_token_reserves,
        real_sol_reserves,
        real_token_reserves,
        creator,
        ix_name,
        is_mayhem_mode,
        quote_mint,
        cashback_fee_basis_points,
    })
}

fn amm_buy(data: &[u8]) -> Result<AmmBuyEvent, PumpError> {
    let mut c = Cursor(data);
    let w = "BuyEvent";
    c.i64(w)?; // timestamp
    let base_amount_out = c.u64(w)?;
    c.u64(w)?; // max_quote_amount_in
    c.u64(w)?; // user_base_token_reserves
    c.u64(w)?; // user_quote_token_reserves
    let pool_base_token_reserves = c.u64(w)?;
    let pool_quote_token_reserves = c.u64(w)?;
    let quote_amount_in = c.u64(w)?;
    c.u64(w)?; // lp_fee_basis_points
    let lp_fee = c.u64(w)?;
    for _ in 0..3 {
        c.u64(w)?; // protocol_fee_basis_points, protocol_fee, quote_amount_in_with_lp_fee
    }
    let user_quote_amount_in = c.u64(w)?;
    let pool = c.key(w)?;
    let user = c.key(w)?;
    for _ in 0..4 {
        c.key(w)?; // user_base/quote_token_account, protocol_fee_recipient (+ son compte)
    }
    let coin_creator = c.key(w)?;
    let coin_creator_fee_basis_points = c.u64(w)?;
    let mut tail = || -> Result<(String, u64, i128), PumpError> {
        c.u64(w)?; // coin_creator_fee
        c.bool(w)?; // track_volume
        for _ in 0..3 {
            c.u64(w)?; // total_unclaimed_tokens, total_claimed_tokens, current_sol_volume
        }
        c.i64(w)?; // last_update_timestamp
        c.u64(w)?; // min_base_amount_out
        let ix_name = c.string(w)?;
        let cashback_bps = c.u64(w)?;
        for _ in 0..3 {
            c.u64(w)?; // cashback, buyback_fee_basis_points, buyback_fee
        }
        let virtual_quote = i128::from_le_bytes(
            c.take(16, w)?
                .try_into()
                .map_err(|_| PumpError::BadAccount(w))?,
        );
        Ok((ix_name, cashback_bps, virtual_quote))
    };
    let (ix_name, cashback_fee_basis_points, virtual_quote_reserves) = tail().unwrap_or_default();
    Ok(AmmBuyEvent {
        pool,
        user,
        user_quote_amount_in,
        pool_base_token_reserves,
        pool_quote_token_reserves,
        base_amount_out,
        quote_amount_in,
        lp_fee,
        coin_creator,
        coin_creator_fee_basis_points,
        ix_name,
        cashback_fee_basis_points,
        virtual_quote_reserves,
    })
}

fn amm_sell(data: &[u8]) -> Result<AmmSellEvent, PumpError> {
    let mut c = Cursor(data);
    let w = "SellEvent";
    c.i64(w)?; // timestamp
    let base_amount_in = c.u64(w)?;
    for _ in 0..3 {
        c.u64(w)?; // min_quote_amount_out, user_base_token_reserves, user_quote_token_reserves
    }
    let pool_base_token_reserves = c.u64(w)?;
    let pool_quote_token_reserves = c.u64(w)?;
    for _ in 0..5 {
        c.u64(w)?; // quote_amount_out, lp_fee_basis_points, lp_fee, protocol_fee_basis_points, protocol_fee
    }
    let quote_amount_out_without_lp_fee = c.u64(w)?;
    c.u64(w)?; // user_quote_amount_out
    let pool = c.key(w)?;
    let user = c.key(w)?;
    for _ in 0..4 {
        c.key(w)?; // comptes du vendeur et du destinataire des frais protocole
    }
    let coin_creator = c.key(w)?;
    let mut tail = || -> Result<(u64, i128), PumpError> {
        c.u64(w)?; // coin_creator_fee_basis_points
        c.u64(w)?; // coin_creator_fee
        let cashback_bps = c.u64(w)?;
        for _ in 0..3 {
            c.u64(w)?; // cashback, buyback_fee_basis_points, buyback_fee
        }
        let virtual_quote = i128::from_le_bytes(
            c.take(16, w)?
                .try_into()
                .map_err(|_| PumpError::BadAccount(w))?,
        );
        Ok((cashback_bps, virtual_quote))
    };
    let (cashback_fee_basis_points, virtual_quote_reserves) = tail().unwrap_or_default();
    Ok(AmmSellEvent {
        pool,
        user,
        base_amount_in,
        pool_base_token_reserves,
        pool_quote_token_reserves,
        quote_amount_out_without_lp_fee,
        coin_creator,
        cashback_fee_basis_points,
        virtual_quote_reserves,
    })
}

/// Décode une ligne de log. `None` : pas un événement pump.fun reconnu (ou données illisibles).
pub fn decode_log(line: &str) -> Option<Event> {
    let b64 = line.strip_prefix("Program data: ")?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let (disc, body) = data.split_at_checked(8)?;
    match disc {
        d if d == CREATE => create(body).ok().map(Event::Create),
        d if d == TRADE => trade(body).ok().map(Event::Trade),
        d if d == AMM_BUY => amm_buy(body).ok().map(Event::AmmBuy),
        d if d == AMM_SELL => amm_sell(body).ok().map(Event::AmmSell),
        _ => None,
    }
}

/// Tous les événements pump.fun d'une transaction, dans l'ordre.
pub fn decode_logs<S: AsRef<str>>(logs: &[S]) -> Vec<Event> {
    logs.iter().filter_map(|l| decode_log(l.as_ref())).collect()
}

impl crate::BondingCurve {
    /// État de la courbe juste après la transaction de création, SANS appel réseau : réserves de la
    /// création, mises à jour par le dernier achat de la même transaction (achat du créateur) s'il y en a.
    pub fn from_events(events: &[Event]) -> Option<Self> {
        let c = events.iter().find_map(|e| match e {
            Event::Create(c) => Some(c),
            _ => None,
        })?;
        let mut curve = Self {
            virtual_token_reserves: c.virtual_token_reserves,
            virtual_quote_reserves: c.virtual_sol_reserves,
            real_token_reserves: c.real_token_reserves,
            real_quote_reserves: 0,
            token_total_supply: c.token_total_supply,
            complete: false,
            creator: c.creator,
            is_mayhem_mode: c.is_mayhem_mode,
            is_cashback_coin: c.is_cashback_enabled,
            quote_mint: c.quote_mint,
        };
        if let Some(t) = events.iter().rev().find_map(|e| match e {
            Event::Trade(t) if t.mint == c.mint => Some(t),
            _ => None,
        }) {
            curve.virtual_token_reserves = t.virtual_token_reserves;
            curve.virtual_quote_reserves = t.virtual_sol_reserves;
            curve.real_token_reserves = t.real_token_reserves;
            curve.real_quote_reserves = t.real_sol_reserves;
        }
        Some(curve)
    }
}

impl crate::BondingCurve {
    /// État de la courbe juste après un trade observé (réserves publiées par l'événement), sans appel réseau.
    pub fn from_trade(t: &TradeEvent) -> Self {
        Self {
            virtual_token_reserves: t.virtual_token_reserves,
            virtual_quote_reserves: t.virtual_sol_reserves,
            real_token_reserves: t.real_token_reserves,
            real_quote_reserves: t.real_sol_reserves,
            token_total_supply: 1_000_000_000_000_000,
            // Plus aucun token à vendre sur la courbe : elle est terminée (migration).
            complete: t.real_token_reserves == 0,
            creator: t.creator,
            is_mayhem_mode: t.is_mayhem_mode,
            is_cashback_coin: t.cashback_fee_basis_points > 0,
            quote_mint: t.quote_mint,
        }
    }
}
