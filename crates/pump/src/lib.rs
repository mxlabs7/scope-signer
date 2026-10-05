//! Instructions pump.fun (courbe de liaison), construites EXACTEMENT comme le SDK officiel
//! `@pump-fun/pump-sdk@2.0.0` — vérifié sur de vrais coins capturés (tests/fixtures) et accepté par
//! mainnet en simulation (tools/pump-oracle).
//!
//! Achat : `buy_exact_sol_in` (montant de SOL exact : la fee Scope se calcule au lamport près).
//! Vente : `sell`.
//! Comptes : ceux de l'IDL officiel + comptes additionnels du SDK
//! (bonding_curve_v2 en lecture, destinataire du buyback en écriture ; cashback : user_volume_accumulator).
//! v1 de Scope : coins cotés en SOL uniquement. Coins migrés : module [`amm`] (PumpSwap).

pub mod amm;

pub mod cu;
pub mod events;
pub mod volume;

pub use scope_solana::{AccountMeta, Ix as Instruction};
use scope_solana::{Pubkey, find_program_address, pubkey};

pub const PUMP_PROGRAM: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";
pub const FEE_PROGRAM: &str = "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const SYSTEM_PROGRAM: Pubkey = [0; 32];
/// Mint du SOL « enveloppé » (cotation SOL).
pub const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";

const GLOBAL_DISCRIMINATOR: [u8; 8] = [0xa7, 0xe8, 0xe8, 0xb1, 0xc8, 0x6c, 0x72, 0x7f];
const BONDING_CURVE_DISCRIMINATOR: [u8; 8] = [0x17, 0xb7, 0xf8, 0x37, 0x60, 0xd8, 0xac, 0x60];
pub const BUY_EXACT_SOL_IN: [u8; 8] = [0x38, 0xfc, 0x74, 0x08, 0x9e, 0xdf, 0xcd, 0x5f];
pub const SELL: [u8; 8] = [0x33, 0xe6, 0x85, 0xa4, 0x01, 0x7f, 0x83, 0xad];

#[derive(Debug, PartialEq, Eq)]
pub enum PumpError {
    BadAccount(&'static str),
    /// Coin coté autrement qu'en SOL : non pris en charge (v1).
    UnsupportedQuote,
    /// La courbe est terminée : le coin a migré (PumpSwap).
    Complete,
    /// Ancien pool PumpSwap à agrandir avant de pouvoir trader (non pris en charge en v1).
    PoolTooOld,
    NoPda,
}

/// Lecture séquentielle des données Borsh d'un compte Anchor.
struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&[u8], PumpError> {
        if self.0.len() < n {
            return Err(PumpError::BadAccount(what));
        }
        let (h, r) = self.0.split_at(n);
        self.0 = r;
        Ok(h)
    }
    fn u64(&mut self, w: &'static str) -> Result<u64, PumpError> {
        Ok(u64::from_le_bytes(
            self.take(8, w)?
                .try_into()
                .map_err(|_| PumpError::BadAccount(w))?,
        ))
    }
    fn bool(&mut self, w: &'static str) -> Result<bool, PumpError> {
        Ok(self.take(1, w)?[0] != 0)
    }
    fn key(&mut self, w: &'static str) -> Result<Pubkey, PumpError> {
        self.take(32, w)?
            .try_into()
            .map_err(|_| PumpError::BadAccount(w))
    }
    fn keys<const N: usize>(&mut self, w: &'static str) -> Result<[Pubkey; N], PumpError> {
        let mut out = [[0u8; 32]; N];
        for k in &mut out {
            *k = self.key(w)?;
        }
        Ok(out)
    }
}

/// Compte « global » de pump.fun (champs utiles au trading).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Global {
    pub fee_recipient: Pubkey,
    pub fee_basis_points: u64,
    pub creator_fee_basis_points: u64,
    pub fee_recipients: [Pubkey; 7],
    pub reserved_fee_recipient: Pubkey,
    pub reserved_fee_recipients: [Pubkey; 7],
    pub buyback_fee_recipients: [Pubkey; 8],
}

impl Global {
    pub fn decode(data: &[u8]) -> Result<Self, PumpError> {
        if data.get(..8) != Some(&GLOBAL_DISCRIMINATOR[..]) {
            return Err(PumpError::BadAccount("global"));
        }
        let mut c = Cursor(&data[8..]);
        let w = "global";
        c.bool(w)?; // initialized
        c.key(w)?; // authority
        let fee_recipient = c.key(w)?;
        for _ in 0..4 {
            c.u64(w)?; // réserves initiales + offre totale
        }
        let fee_basis_points = c.u64(w)?;
        c.key(w)?; // withdraw_authority
        c.bool(w)?; // enable_migrate
        c.u64(w)?; // pool_migration_fee
        let creator_fee_basis_points = c.u64(w)?;
        let fee_recipients = c.keys::<7>(w)?;
        c.key(w)?; // set_creator_authority
        c.key(w)?; // admin_set_creator_authority
        c.bool(w)?; // create_v2_enabled
        c.key(w)?; // whitelist_pda
        let reserved_fee_recipient = c.key(w)?;
        c.bool(w)?; // mayhem_mode_enabled
        let reserved_fee_recipients = c.keys::<7>(w)?;
        c.bool(w)?; // is_cashback_enabled
        let buyback_fee_recipients = c.keys::<8>(w)?;
        Ok(Self {
            fee_recipient,
            fee_basis_points,
            creator_fee_basis_points,
            fee_recipients,
            reserved_fee_recipient,
            reserved_fee_recipients,
            buyback_fee_recipients,
        })
    }

    /// Destinataires possibles des fees pump.fun (liste réservée pour les coins Mayhem), comme le SDK.
    pub fn fee_recipients_for(&self, mayhem: bool) -> [Pubkey; 8] {
        let (first, rest) = if mayhem {
            (self.reserved_fee_recipient, &self.reserved_fee_recipients)
        } else {
            (self.fee_recipient, &self.fee_recipients)
        };
        let mut out = [first; 8];
        out[1..].copy_from_slice(rest);
        out
    }
}

/// Compte « bonding curve » d'un coin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondingCurve {
    pub virtual_token_reserves: u64,
    pub virtual_quote_reserves: u64,
    pub real_token_reserves: u64,
    pub real_quote_reserves: u64,
    pub token_total_supply: u64,
    pub complete: bool,
    pub creator: Pubkey,
    pub is_mayhem_mode: bool,
    pub is_cashback_coin: bool,
    pub quote_mint: Pubkey,
}

impl BondingCurve {
    pub fn decode(data: &[u8]) -> Result<Self, PumpError> {
        if data.get(..8) != Some(&BONDING_CURVE_DISCRIMINATOR[..]) {
            return Err(PumpError::BadAccount("bonding curve"));
        }
        let mut c = Cursor(&data[8..]);
        let w = "bonding curve";
        Ok(Self {
            virtual_token_reserves: c.u64(w)?,
            virtual_quote_reserves: c.u64(w)?,
            real_token_reserves: c.u64(w)?,
            real_quote_reserves: c.u64(w)?,
            token_total_supply: c.u64(w)?,
            complete: c.bool(w)?,
            creator: c.key(w)?,
            is_mayhem_mode: c.bool(w)?,
            is_cashback_coin: c.bool(w)?,
            // Anciennes courbes (plus courtes) : cotation SOL implicite.
            quote_mint: c.key(w).unwrap_or([0; 32]),
        })
    }

    /// Cotation SOL (mint vide sur les anciennes courbes, ou WSOL).
    pub fn is_sol_quoted(&self) -> bool {
        self.quote_mint == [0; 32] || pubkey(WSOL_MINT) == Some(self.quote_mint)
    }
}

fn ro(pubkey: Pubkey) -> AccountMeta {
    AccountMeta {
        pubkey,
        signer: false,
        writable: false,
    }
}
fn rw(pubkey: Pubkey) -> AccountMeta {
    AccountMeta {
        pubkey,
        signer: false,
        writable: true,
    }
}

fn key(s: &str) -> Result<Pubkey, PumpError> {
    pubkey(s).ok_or(PumpError::NoPda)
}

fn pda(seeds: &[&[u8]], program: &str) -> Result<Pubkey, PumpError> {
    find_program_address(seeds, &key(program)?).ok_or(PumpError::NoPda)
}

/// Adresses dérivées d'un coin et d'un acheteur, calculées hors ligne (zéro RPC).
pub struct Pdas {
    pub global: Pubkey,
    pub bonding_curve: Pubkey,
    pub bonding_curve_v2: Pubkey,
    pub associated_bonding_curve: Pubkey,
    pub associated_user: Pubkey,
    pub creator_vault: Pubkey,
    pub event_authority: Pubkey,
    pub global_volume_accumulator: Pubkey,
    pub user_volume_accumulator: Pubkey,
    pub fee_config: Pubkey,
}

impl Pdas {
    pub fn new(
        mint: &Pubkey,
        token_program: &Pubkey,
        user: &Pubkey,
        creator: &Pubkey,
    ) -> Result<Self, PumpError> {
        let bonding_curve = pda(&[b"bonding-curve", mint], PUMP_PROGRAM)?;
        let ata = |owner: &Pubkey| pda(&[owner, token_program, mint], ATA_PROGRAM);
        Ok(Self {
            global: pda(&[b"global"], PUMP_PROGRAM)?,
            bonding_curve_v2: pda(&[b"bonding-curve-v2", mint], PUMP_PROGRAM)?,
            associated_bonding_curve: ata(&bonding_curve)?,
            associated_user: ata(user)?,
            bonding_curve,
            creator_vault: pda(&[b"creator-vault", creator], PUMP_PROGRAM)?,
            event_authority: pda(&[b"__event_authority"], PUMP_PROGRAM)?,
            global_volume_accumulator: pda(&[b"global_volume_accumulator"], PUMP_PROGRAM)?,
            user_volume_accumulator: pda(&[b"user_volume_accumulator", user], PUMP_PROGRAM)?,
            fee_config: pda(&[b"fee_config", &key(PUMP_PROGRAM)?], FEE_PROGRAM)?,
        })
    }
}

/// Paramètres communs d'un trade sur la courbe.
pub struct Trade<'a> {
    pub global: &'a Global,
    pub curve: &'a BondingCurve,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub user: Pubkey,
    /// Index (0-7) du destinataire des fees pump.fun et du buyback ; le SDK les tire au hasard.
    pub fee_recipient_index: usize,
    pub buyback_index: usize,
}

impl Trade<'_> {
    fn check(&self) -> Result<Pdas, PumpError> {
        if self.curve.complete {
            return Err(PumpError::Complete);
        }
        if !self.curve.is_sol_quoted() {
            return Err(PumpError::UnsupportedQuote);
        }
        Pdas::new(
            &self.mint,
            &self.token_program,
            &self.user,
            &self.curve.creator,
        )
    }

    fn fee_recipient(&self) -> Pubkey {
        self.global.fee_recipients_for(self.curve.is_mayhem_mode)[self.fee_recipient_index % 8]
    }

    fn buyback(&self) -> Pubkey {
        self.global.buyback_fee_recipients[self.buyback_index % 8]
    }

    /// Achat d'un montant de SOL EXACT (`buy_exact_sol_in`). `min_tokens_out` ≥ 1 (0 est refusé par le programme).
    pub fn buy_exact_sol_in(
        &self,
        sol_in: u64,
        min_tokens_out: u64,
    ) -> Result<Instruction, PumpError> {
        let p = self.check()?;
        let mut data = BUY_EXACT_SOL_IN.to_vec();
        data.extend_from_slice(&sol_in.to_le_bytes());
        data.extend_from_slice(&min_tokens_out.max(1).to_le_bytes());
        data.push(1); // track_volume = Some(true)
        Ok(Instruction {
            program: key(PUMP_PROGRAM)?,
            accounts: vec![
                ro(p.global),
                rw(self.fee_recipient()),
                ro(self.mint),
                rw(p.bonding_curve),
                rw(p.associated_bonding_curve),
                rw(p.associated_user),
                AccountMeta {
                    pubkey: self.user,
                    signer: true,
                    writable: true,
                },
                ro(SYSTEM_PROGRAM),
                ro(self.token_program),
                rw(p.creator_vault),
                ro(p.event_authority),
                ro(key(PUMP_PROGRAM)?),
                ro(p.global_volume_accumulator),
                rw(p.user_volume_accumulator),
                ro(p.fee_config),
                ro(key(FEE_PROGRAM)?),
                // Comptes additionnels exigés par le programme actuel (comme le SDK).
                ro(p.bonding_curve_v2),
                rw(self.buyback()),
            ],
            data,
        })
    }

    /// Vente de `amount` tokens, avec un minimum de SOL garanti.
    pub fn sell(&self, amount: u64, min_sol_output: u64) -> Result<Instruction, PumpError> {
        let p = self.check()?;
        let mut data = SELL.to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&min_sol_output.to_le_bytes());
        let mut accounts = vec![
            ro(p.global),
            rw(self.fee_recipient()),
            ro(self.mint),
            rw(p.bonding_curve),
            rw(p.associated_bonding_curve),
            rw(p.associated_user),
            AccountMeta {
                pubkey: self.user,
                signer: true,
                writable: true,
            },
            ro(SYSTEM_PROGRAM),
            // ⚠️ À la vente, creator_vault et token_program sont INVERSÉS par rapport à l'achat.
            rw(p.creator_vault),
            ro(self.token_program),
            ro(p.event_authority),
            ro(key(PUMP_PROGRAM)?),
            ro(p.fee_config),
            ro(key(FEE_PROGRAM)?),
        ];
        if self.curve.is_cashback_coin {
            accounts.push(rw(p.user_volume_accumulator));
        }
        accounts.push(ro(p.bonding_curve_v2));
        accounts.push(rw(self.buyback()));
        Ok(Instruction {
            program: key(PUMP_PROGRAM)?,
            accounts,
            data,
        })
    }

    /// Fermeture du compte de tokens (vide) : le dépôt de location revient au wallet.
    pub fn close_user_ata(&self) -> Result<Instruction, PumpError> {
        let p = Pdas::new(
            &self.mint,
            &self.token_program,
            &self.user,
            &self.curve.creator,
        )?;
        Ok(Instruction {
            program: self.token_program,
            accounts: vec![
                rw(p.associated_user),
                rw(self.user),
                AccountMeta {
                    pubkey: self.user,
                    signer: true,
                    writable: false,
                },
            ],
            data: vec![9], // CloseAccount
        })
    }

    /// Création idempotente du compte de tokens de l'acheteur (sans effet s'il existe).
    pub fn create_user_ata(&self) -> Result<Instruction, PumpError> {
        let p = Pdas::new(
            &self.mint,
            &self.token_program,
            &self.user,
            &self.curve.creator,
        )?;
        Ok(Instruction {
            program: key(ATA_PROGRAM)?,
            accounts: vec![
                AccountMeta {
                    pubkey: self.user,
                    signer: true,
                    writable: true,
                },
                rw(p.associated_user),
                ro(self.user),
                ro(self.mint),
                ro(SYSTEM_PROGRAM),
                ro(self.token_program),
            ],
            data: vec![1],
        })
    }
}

// ---------- Estimations (prudentes) ----------

/// Frais pump.fun supposés pour les estimations : un peu AU-DESSUS du barème réel (protocole + créateur),
/// pour que le minimum garanti reste atteignable. Vérifié contre le SDK sur les coins capturés.
pub const FEE_ESTIMATE_BPS: u128 = 250;

impl BondingCurve {
    /// Tokens reçus (estimation prudente) pour `sol_in` lamports dépensés, frais compris.
    pub fn estimate_tokens_out(&self, sol_in: u64) -> u64 {
        let (vt, vq) = (
            u128::from(self.virtual_token_reserves),
            u128::from(self.virtual_quote_reserves),
        );
        let net = u128::from(sol_in.saturating_sub(1)) * 10_000 / (10_000 + FEE_ESTIMATE_BPS);
        if vq + net == 0 {
            return 0;
        }
        let out = net * vt / (vq + net);
        u64::try_from(out.min(u128::from(self.real_token_reserves))).unwrap_or(0)
    }

    /// SOL reçu (estimation prudente, frais déduits) pour la vente de `tokens`.
    pub fn estimate_sol_out(&self, tokens: u64) -> u64 {
        let (vt, vq) = (
            u128::from(self.virtual_token_reserves),
            u128::from(self.virtual_quote_reserves),
        );
        if vt + u128::from(tokens) == 0 {
            return 0;
        }
        let gross = u128::from(tokens) * vq / (vt + u128::from(tokens));
        u64::try_from(gross * (10_000 - FEE_ESTIMATE_BPS) / 10_000).unwrap_or(0)
    }
}

/// Applique une tolérance de prix (slippage, en points de base) à un montant attendu.
pub fn with_slippage(amount: u64, slippage_bps: u16) -> u64 {
    let keep = 10_000u128.saturating_sub(u128::from(slippage_bps.min(10_000)));
    u64::try_from(u128::from(amount) * keep / 10_000).unwrap_or(0)
}
