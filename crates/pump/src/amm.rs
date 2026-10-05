//! PumpSwap (coins migrés de la courbe), construit comme le SDK officiel `@pump-fun/pump-swap-sdk@1.20.0`
//! — vérifié sur de vrais pools capturés (tests/fixtures/amm) et accepté par mainnet en simulation.
//!
//! Achat : `buy_exact_quote_in` (montant de SOL exact : la fee Scope se calcule au lamport près ;
//! le SDK utilise `buy`, mêmes comptes). Vente : `sell`.
//! Le SOL passe par le compte WSOL du wallet : créé, approvisionné, puis refermé dans la même transaction.
//! v1 de Scope : pools canoniques pump.fun cotés en SOL uniquement.

use scope_solana::Pubkey;

use crate::{
    ATA_PROGRAM, AccountMeta, Cursor, FEE_PROGRAM, Instruction, PUMP_PROGRAM, PumpError,
    SYSTEM_PROGRAM, WSOL_MINT, key, pda, ro, rw,
};

pub const AMM_PROGRAM: &str = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA";
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

const GLOBAL_CONFIG_DISCRIMINATOR: [u8; 8] = [0x95, 0x08, 0x9c, 0xca, 0xa0, 0xfc, 0xb0, 0xd9];
const POOL_DISCRIMINATOR: [u8; 8] = [0xf1, 0x9a, 0x6d, 0x04, 0x11, 0xb1, 0x6d, 0xbc];
pub const BUY_EXACT_QUOTE_IN: [u8; 8] = [0xc6, 0x2e, 0x15, 0x52, 0xb4, 0xd9, 0xe8, 0x70];
pub const SELL: [u8; 8] = [0x33, 0xe6, 0x85, 0xa4, 0x01, 0x7f, 0x83, 0xad];

/// Tailles actuelles (discriminateur compris). Les anciens comptes sont plus courts : les champs
/// manquants valent 0 / false, comme le lit le programme.
const GLOBAL_CONFIG_SIZE: usize = 949;
const POOL_SIZE: usize = 270;
/// Un pool plus petit doit d'abord être agrandi (`extend_account`) : non pris en charge (v1).
pub const POOL_MIN_LEN: usize = 300;

fn padded(data: &[u8], size: usize) -> Vec<u8> {
    let mut v = data.to_vec();
    if v.len() < size {
        v.resize(size, 0);
    }
    v
}

/// Configuration globale de PumpSwap (champs utiles au trading).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalConfig {
    pub protocol_fee_recipients: [Pubkey; 8],
    pub reserved_fee_recipient: Pubkey,
    pub reserved_fee_recipients: [Pubkey; 7],
    pub buyback_fee_recipients: [Pubkey; 8],
}

impl GlobalConfig {
    pub fn decode(data: &[u8]) -> Result<Self, PumpError> {
        if data.get(..8) != Some(&GLOBAL_CONFIG_DISCRIMINATOR[..]) {
            return Err(PumpError::BadAccount("global config"));
        }
        let data = padded(data, GLOBAL_CONFIG_SIZE);
        let mut c = Cursor(&data[8..]);
        let w = "global config";
        c.key(w)?; // admin
        c.u64(w)?; // lp_fee_basis_points
        c.u64(w)?; // protocol_fee_basis_points
        c.take(1, w)?; // disable_flags
        let protocol_fee_recipients = c.keys::<8>(w)?;
        c.u64(w)?; // coin_creator_fee_basis_points
        c.key(w)?; // admin_set_coin_creator_authority
        c.key(w)?; // whitelist_pda
        let reserved_fee_recipient = c.key(w)?;
        c.bool(w)?; // mayhem_mode_enabled
        let reserved_fee_recipients = c.keys::<7>(w)?;
        c.bool(w)?; // is_cashback_enabled
        let buyback_fee_recipients = c.keys::<8>(w)?;
        Ok(Self {
            protocol_fee_recipients,
            reserved_fee_recipient,
            reserved_fee_recipients,
            buyback_fee_recipients,
        })
    }

    /// Destinataires possibles des fees du protocole (liste réservée pour les pools Mayhem), comme le SDK.
    pub fn fee_recipients_for(&self, mayhem: bool) -> [Pubkey; 8] {
        if !mayhem {
            return self.protocol_fee_recipients;
        }
        let mut out = [self.reserved_fee_recipient; 8];
        out[1..].copy_from_slice(&self.reserved_fee_recipients);
        out
    }
}

/// Pool PumpSwap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    pub creator: Pubkey,
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub pool_base_token_account: Pubkey,
    pub pool_quote_token_account: Pubkey,
    pub coin_creator: Pubkey,
    pub is_mayhem_mode: bool,
    pub is_cashback_coin: bool,
    /// Réserve de SOL virtuelle ajoutée à la réserve réelle dans le calcul du prix.
    pub virtual_quote_reserves: i128,
    /// Part créateur propre au pool (0 = barème standard).
    pub creator_fee_bps: u64,
    /// Taille du compte on-chain.
    pub len: usize,
}

impl Pool {
    pub fn decode(data: &[u8]) -> Result<Self, PumpError> {
        if data.get(..8) != Some(&POOL_DISCRIMINATOR[..]) {
            return Err(PumpError::BadAccount("pool"));
        }
        let len = data.len();
        let data = padded(data, POOL_SIZE);
        let mut c = Cursor(&data[8..]);
        let w = "pool";
        c.take(1, w)?; // pool_bump
        c.take(2, w)?; // index
        let creator = c.key(w)?;
        let base_mint = c.key(w)?;
        let quote_mint = c.key(w)?;
        c.key(w)?; // lp_mint
        let pool_base_token_account = c.key(w)?;
        let pool_quote_token_account = c.key(w)?;
        c.u64(w)?; // lp_supply
        let coin_creator = c.key(w)?;
        let is_mayhem_mode = c.bool(w)?;
        let is_cashback_coin = c.bool(w)?;
        let virtual_quote_reserves = i128::from_le_bytes(
            c.take(16, w)?
                .try_into()
                .map_err(|_| PumpError::BadAccount(w))?,
        );
        let creator_fee_bps = c.u64(w)?;
        Ok(Self {
            creator,
            base_mint,
            quote_mint,
            pool_base_token_account,
            pool_quote_token_account,
            coin_creator,
            is_mayhem_mode,
            is_cashback_coin,
            virtual_quote_reserves,
            creator_fee_bps,
            len,
        })
    }
}

/// Pool canonique d'un coin pump.fun migré, coté en SOL (zéro RPC).
pub fn canonical_pool(mint: &Pubkey) -> Result<Pubkey, PumpError> {
    let authority = pda(&[b"pool-authority", mint], PUMP_PROGRAM)?;
    pda(
        &[
            b"pool",
            &0u16.to_le_bytes(),
            &authority,
            mint,
            &key(WSOL_MINT)?,
        ],
        AMM_PROGRAM,
    )
}

fn ata(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Result<Pubkey, PumpError> {
    pda(&[owner, token_program, mint], ATA_PROGRAM)
}

fn signer(pubkey: Pubkey) -> AccountMeta {
    AccountMeta {
        pubkey,
        signer: true,
        writable: true,
    }
}

/// Paramètres communs d'un swap PumpSwap.
pub struct Swap<'a> {
    pub config: &'a GlobalConfig,
    pub pool: &'a Pool,
    pub pool_key: Pubkey,
    /// Programme de token du coin (Token ou Token-2022, propriétaire du mint).
    pub base_token_program: Pubkey,
    pub user: Pubkey,
    /// Index (0-7) du destinataire des fees du protocole et du buyback ; le SDK les tire au hasard.
    pub fee_recipient_index: usize,
    pub buyback_index: usize,
}

impl Swap<'_> {
    fn check(&self) -> Result<(), PumpError> {
        if self.pool.quote_mint != key(WSOL_MINT)? {
            return Err(PumpError::UnsupportedQuote);
        }
        if self.pool.len < POOL_MIN_LEN {
            return Err(PumpError::PoolTooOld);
        }
        Ok(())
    }

    fn wsol(&self) -> Result<Pubkey, PumpError> {
        ata(&self.user, &key(WSOL_MINT)?, &key(TOKEN_PROGRAM)?)
    }

    fn user_base(&self) -> Result<Pubkey, PumpError> {
        ata(&self.user, &self.pool.base_mint, &self.base_token_program)
    }

    fn user_volume_accumulator(&self) -> Result<Pubkey, PumpError> {
        pda(&[b"user_volume_accumulator", &self.user], AMM_PROGRAM)
    }

    /// Comptes 0-18, communs à l'achat et à la vente (ordre de l'IDL).
    fn common_accounts(&self) -> Result<Vec<AccountMeta>, PumpError> {
        let (wsol_mint, token) = (key(WSOL_MINT)?, key(TOKEN_PROGRAM)?);
        let fee_recipient =
            self.config.fee_recipients_for(self.pool.is_mayhem_mode)[self.fee_recipient_index % 8];
        let vault_authority = pda(&[b"creator_vault", &self.pool.coin_creator], AMM_PROGRAM)?;
        Ok(vec![
            rw(self.pool_key),
            signer(self.user),
            ro(pda(&[b"global_config"], AMM_PROGRAM)?),
            ro(self.pool.base_mint),
            ro(wsol_mint),
            rw(self.user_base()?),
            rw(self.wsol()?),
            rw(self.pool.pool_base_token_account),
            rw(self.pool.pool_quote_token_account),
            ro(fee_recipient),
            rw(ata(&fee_recipient, &wsol_mint, &token)?),
            ro(self.base_token_program),
            ro(token),
            ro(SYSTEM_PROGRAM),
            ro(key(ATA_PROGRAM)?),
            ro(pda(&[b"__event_authority"], AMM_PROGRAM)?),
            ro(key(AMM_PROGRAM)?),
            rw(ata(&vault_authority, &wsol_mint, &token)?),
            ro(vault_authority),
        ])
    }

    fn fee_config(&self) -> Result<Pubkey, PumpError> {
        pda(&[b"fee_config", &key(AMM_PROGRAM)?], FEE_PROGRAM)
    }

    /// Comptes additionnels exigés par le programme actuel (comme le SDK).
    fn remaining(&self, sell: bool) -> Result<Vec<AccountMeta>, PumpError> {
        let (wsol_mint, token) = (key(WSOL_MINT)?, key(TOKEN_PROGRAM)?);
        let mut out = Vec::new();
        if self.pool.is_cashback_coin {
            let uva = self.user_volume_accumulator()?;
            out.push(rw(ata(&uva, &wsol_mint, &token)?));
            if sell {
                out.push(rw(uva));
            }
        }
        if self.pool.coin_creator != [0; 32] {
            out.push(ro(pda(&[b"pool-v2", &self.pool.base_mint], AMM_PROGRAM)?));
        }
        let buyback = self.config.buyback_fee_recipients[self.buyback_index % 8];
        out.push(ro(buyback));
        out.push(rw(ata(&buyback, &wsol_mint, &token)?));
        Ok(out)
    }

    /// Achat pour un montant de SOL EXACT (frais PumpSwap compris). `min_base_out` ≥ 1.
    pub fn buy_exact_quote_in(
        &self,
        sol_in: u64,
        min_base_out: u64,
    ) -> Result<Instruction, PumpError> {
        self.check()?;
        let mut data = BUY_EXACT_QUOTE_IN.to_vec();
        data.extend_from_slice(&sol_in.to_le_bytes());
        data.extend_from_slice(&min_base_out.max(1).to_le_bytes());
        data.push(1); // track_volume = true (comme le SDK)
        let mut accounts = self.common_accounts()?;
        accounts.extend([
            ro(pda(&[b"global_volume_accumulator"], AMM_PROGRAM)?),
            rw(self.user_volume_accumulator()?),
            ro(self.fee_config()?),
            ro(key(FEE_PROGRAM)?),
        ]);
        accounts.extend(self.remaining(false)?);
        Ok(Instruction {
            program: key(AMM_PROGRAM)?,
            accounts,
            data,
        })
    }

    /// Vente de `base_in` tokens, avec un minimum de SOL garanti.
    pub fn sell(&self, base_in: u64, min_sol_out: u64) -> Result<Instruction, PumpError> {
        self.check()?;
        let mut data = SELL.to_vec();
        data.extend_from_slice(&base_in.to_le_bytes());
        data.extend_from_slice(&min_sol_out.to_le_bytes());
        let mut accounts = self.common_accounts()?;
        accounts.extend([ro(self.fee_config()?), ro(key(FEE_PROGRAM)?)]);
        accounts.extend(self.remaining(true)?);
        Ok(Instruction {
            program: key(AMM_PROGRAM)?,
            accounts,
            data,
        })
    }

    fn create_ata(
        &self,
        account: Pubkey,
        mint: Pubkey,
        program: Pubkey,
    ) -> Result<Instruction, PumpError> {
        Ok(Instruction {
            program: key(ATA_PROGRAM)?,
            accounts: vec![
                signer(self.user),
                rw(account),
                ro(self.user),
                ro(mint),
                ro(SYSTEM_PROGRAM),
                ro(program),
            ],
            data: vec![1], // CreateIdempotent : sans effet si le compte existe
        })
    }

    fn close(&self, account: Pubkey, program: Pubkey) -> Instruction {
        Instruction {
            program,
            accounts: vec![
                rw(account),
                rw(self.user),
                AccountMeta {
                    pubkey: self.user,
                    signer: true,
                    writable: false,
                },
            ],
            data: vec![9], // CloseAccount : le contenu revient au wallet
        }
    }

    /// Création idempotente du compte de tokens du coin.
    pub fn create_base_ata(&self) -> Result<Instruction, PumpError> {
        self.create_ata(
            self.user_base()?,
            self.pool.base_mint,
            self.base_token_program,
        )
    }

    /// Fermeture du compte de tokens du coin (vide) : le dépôt revient au wallet.
    pub fn close_base_ata(&self) -> Result<Instruction, PumpError> {
        Ok(self.close(self.user_base()?, self.base_token_program))
    }

    /// Compte WSOL du wallet : création (idempotente) puis, si `lamports` > 0, dépôt de SOL + SyncNative.
    pub fn open_wsol(&self, lamports: u64) -> Result<Vec<Instruction>, PumpError> {
        let (wsol, token) = (self.wsol()?, key(TOKEN_PROGRAM)?);
        let mut out = vec![self.create_ata(wsol, key(WSOL_MINT)?, token)?];
        if lamports > 0 {
            out.push(scope_solana::transfer(&self.user, &wsol, lamports));
            out.push(Instruction {
                program: token,
                accounts: vec![rw(wsol)],
                data: vec![17], // SyncNative
            });
        }
        Ok(out)
    }

    /// Fermeture du compte WSOL : tout son SOL (reste de l'achat ou produit de la vente) revient au wallet.
    pub fn close_wsol(&self) -> Result<Instruction, PumpError> {
        Ok(self.close(self.wsol()?, key(TOKEN_PROGRAM)?))
    }
}

// ---------- Estimations (prudentes) ----------

/// Plafond des frais LP + protocole du barème PumpSwap (0,95 % au plus, relevé on-chain le 03/10/2026).
const LP_PROTOCOL_ESTIMATE_BPS: u128 = 95;
/// Part créateur supposée au minimum (plafond du barème standard).
const CREATOR_ESTIMATE_BPS: u128 = 95;

impl Pool {
    /// Frais supposés : toujours AU-DESSUS du barème réel, pour que le minimum garanti reste atteignable.
    fn fee_estimate_bps(&self) -> u128 {
        LP_PROTOCOL_ESTIMATE_BPS + CREATOR_ESTIMATE_BPS.max(u128::from(self.creator_fee_bps))
    }

    fn effective_quote(&self, quote_reserve: u64) -> u128 {
        u128::try_from(i128::from(quote_reserve).saturating_add(self.virtual_quote_reserves))
            .unwrap_or(0)
    }

    /// Tokens reçus (estimation prudente) pour `sol_in` lamports dépensés, frais compris.
    pub fn estimate_base_out(&self, sol_in: u64, base_reserve: u64, quote_reserve: u64) -> u64 {
        let q = self.effective_quote(quote_reserve);
        let net =
            u128::from(sol_in.saturating_sub(1)) * 10_000 / (10_000 + self.fee_estimate_bps());
        if q + net == 0 {
            return 0;
        }
        u64::try_from(u128::from(base_reserve) * net / (q + net)).unwrap_or(0)
    }

    /// SOL reçu (estimation prudente, frais déduits) pour la vente de `base_in` tokens.
    pub fn estimate_sol_out(&self, base_in: u64, base_reserve: u64, quote_reserve: u64) -> u64 {
        let denom = u128::from(base_reserve) + u128::from(base_in);
        if denom == 0 {
            return 0;
        }
        let gross = self.effective_quote(quote_reserve) * u128::from(base_in) / denom;
        let net = gross * (10_000 - self.fee_estimate_bps().min(10_000)) / 10_000;
        u64::try_from(net.min(u128::from(quote_reserve))).unwrap_or(0)
    }
}

impl Pool {
    /// Pool canonique reconstruit SANS appel réseau à partir d'un achat observé et du mint du coin :
    /// adresses dérivées (comptes de réserve = comptes associés du pool), le reste publié par l'achat.
    /// Renvoie aussi l'adresse du pool, qui doit être celle de l'achat (sinon : pool non canonique).
    pub fn from_buy(
        mint: &Pubkey,
        base_token_program: &Pubkey,
        ev: &crate::events::AmmBuyEvent,
    ) -> Result<Option<(Pubkey, Self)>, PumpError> {
        Self::canonical(
            mint,
            base_token_program,
            &ev.pool,
            ev.coin_creator,
            ev.cashback_fee_basis_points,
            ev.virtual_quote_reserves,
        )
    }

    /// Même chose à partir d'une vente observée.
    pub fn from_sell(
        mint: &Pubkey,
        base_token_program: &Pubkey,
        ev: &crate::events::AmmSellEvent,
    ) -> Result<Option<(Pubkey, Self)>, PumpError> {
        Self::canonical(
            mint,
            base_token_program,
            &ev.pool,
            ev.coin_creator,
            ev.cashback_fee_basis_points,
            ev.virtual_quote_reserves,
        )
    }

    fn canonical(
        mint: &Pubkey,
        base_token_program: &Pubkey,
        pool: &Pubkey,
        coin_creator: Pubkey,
        cashback_bps: u64,
        virtual_quote_reserves: i128,
    ) -> Result<Option<(Pubkey, Self)>, PumpError> {
        let pool_key = canonical_pool(mint)?;
        if pool_key != *pool {
            return Ok(None);
        }
        let (wsol, token) = (key(WSOL_MINT)?, key(TOKEN_PROGRAM)?);
        Ok(Some((
            pool_key,
            Self {
                creator: pda(&[b"pool-authority", mint], PUMP_PROGRAM)?,
                base_mint: *mint,
                quote_mint: wsol,
                pool_base_token_account: ata(&pool_key, mint, base_token_program)?,
                pool_quote_token_account: ata(&pool_key, &wsol, &token)?,
                coin_creator,
                is_mayhem_mode: false,
                is_cashback_coin: cashback_bps > 0,
                virtual_quote_reserves,
                creator_fee_bps: 0,
                // Le trade observé a réussi : le pool est à jour.
                len: POOL_MIN_LEN,
            },
        )))
    }
}
