//! Compteurs de volume pump.fun (un par wallet et par programme : courbe, PumpSwap), créés par pump.fun
//! au premier achat (~0,0013 SOL de dépôt). On peut les fermer pour récupérer ce dépôt — mais ils
//! contiennent aussi les RÉCOMPENSES du wallet (tokens PUMP du programme de volume, cashback des coins
//! cashback) : on ne ferme jamais un compteur qui en contient encore.
//!
//! - cashback en attente : réclamé dans la même transaction, juste avant la fermeture ;
//! - récompenses PUMP en attente (programme de volume actif) : on REFUSE de fermer (elles seraient perdues).

use scope_solana::Pubkey;

use crate::amm::{AMM_PROGRAM, TOKEN_PROGRAM};
use crate::{
    ATA_PROGRAM, AccountMeta, Cursor, Instruction, PUMP_PROGRAM, PumpError, SYSTEM_PROGRAM,
    WSOL_MINT, key, pda, ro, rw,
};

const USER_DISCRIMINATOR: [u8; 8] = [0x56, 0xff, 0x70, 0x0e, 0x66, 0x35, 0x9a, 0xfa];
const GLOBAL_DISCRIMINATOR: [u8; 8] = [0xca, 0x2a, 0xf6, 0x2b, 0x8e, 0xbe, 0x1e, 0xff];
pub const CLOSE: [u8; 8] = [0xf9, 0x45, 0xa4, 0xda, 0x96, 0x67, 0x54, 0x8a];
pub const CLAIM_CASHBACK: [u8; 8] = [0x25, 0x3a, 0x23, 0x7e, 0xbe, 0x35, 0xe4, 0xc5];
/// Taille actuelle d'un compteur (discriminateur compris) ; les anciens sont plus courts (champs à 0).
const USER_SIZE: usize = 106;

/// Programme du compteur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Market {
    Curve,
    PumpSwap,
}

impl Market {
    fn program(self) -> &'static str {
        match self {
            Market::Curve => PUMP_PROGRAM,
            Market::PumpSwap => AMM_PROGRAM,
        }
    }
}

/// Compteur de volume d'un wallet (champs utiles).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserVolume {
    pub total_unclaimed_tokens: u64,
    pub current_sol_volume: u64,
    pub cashback_earned: u64,
    pub total_cashback_claimed: u64,
    pub stable_cashback_earned: u64,
    pub total_stable_cashback_claimed: u64,
}

impl UserVolume {
    pub fn decode(data: &[u8]) -> Result<Self, PumpError> {
        if data.get(..8) != Some(&USER_DISCRIMINATOR[..]) {
            return Err(PumpError::BadAccount("compteur de volume"));
        }
        let mut d = data.to_vec();
        if d.len() < USER_SIZE {
            d.resize(USER_SIZE, 0);
        }
        let mut c = Cursor(&d[8..]);
        let w = "compteur de volume";
        c.key(w)?; // user
        c.bool(w)?; // needs_claim
        let total_unclaimed_tokens = c.u64(w)?;
        c.u64(w)?; // total_claimed_tokens
        let current_sol_volume = c.u64(w)?;
        c.u64(w)?; // last_update_timestamp
        c.bool(w)?; // has_total_claimed_tokens
        Ok(Self {
            total_unclaimed_tokens,
            current_sol_volume,
            cashback_earned: c.u64(w)?,
            total_cashback_claimed: c.u64(w)?,
            stable_cashback_earned: c.u64(w)?,
            total_stable_cashback_claimed: c.u64(w)?,
        })
    }

    /// Cashback en SOL pas encore réclamé.
    pub fn pending_cashback(&self) -> u64 {
        self.cashback_earned
            .saturating_sub(self.total_cashback_claimed)
    }
}

/// Le programme de récompenses PUMP (au volume) est-il actif ? (dates à 0 = inactif)
pub fn incentives_active(global_data: &[u8]) -> Result<bool, PumpError> {
    if global_data.get(..8) != Some(&GLOBAL_DISCRIMINATOR[..]) {
        return Err(PumpError::BadAccount("compteur global"));
    }
    let mut c = Cursor(&global_data[8..]);
    let w = "compteur global";
    let (start, end) = (c.u64(w)?, c.u64(w)?);
    Ok(start != 0 && end != 0)
}

/// Pourquoi un compteur ne peut pas être fermé.
#[derive(Debug, PartialEq, Eq)]
pub enum Blocked {
    /// Récompenses PUMP en attente (ou en cours d'accumulation aujourd'hui) : elles seraient perdues.
    PumpRewards,
    /// Cashback en stablecoin (non géré en v1) : il serait perdu.
    StableCashback,
}

/// Adresses du compteur (et du compteur global) d'un wallet.
pub fn accounts(market: Market, user: &Pubkey) -> Result<(Pubkey, Pubkey), PumpError> {
    Ok((
        pda(&[b"user_volume_accumulator", user], market.program())?,
        pda(&[b"global_volume_accumulator"], market.program())?,
    ))
}

/// Instructions pour récupérer le dépôt du compteur : cashback réclamé d'abord s'il y en a, puis
/// fermeture. Refus si des récompenses seraient perdues.
pub fn reclaim(
    market: Market,
    user: &Pubkey,
    volume: &UserVolume,
    incentives_active: bool,
) -> Result<Vec<Instruction>, Blocked> {
    if volume.total_unclaimed_tokens > 0 || (incentives_active && volume.current_sol_volume > 0) {
        return Err(Blocked::PumpRewards);
    }
    if volume.stable_cashback_earned > volume.total_stable_cashback_claimed {
        return Err(Blocked::StableCashback);
    }
    let build = || -> Result<Vec<Instruction>, PumpError> {
        let program = key(market.program())?;
        let (uva, _) = accounts(market, user)?;
        let events = pda(&[b"__event_authority"], market.program())?;
        let signer = AccountMeta {
            pubkey: *user,
            signer: true,
            writable: true,
        };
        let mut ixs = Vec::new();
        if volume.pending_cashback() > 0 {
            match market {
                Market::Curve => ixs.push(Instruction {
                    program,
                    accounts: vec![
                        signer.clone(),
                        rw(uva),
                        ro(SYSTEM_PROGRAM),
                        ro(events),
                        ro(program),
                    ],
                    data: CLAIM_CASHBACK.to_vec(),
                }),
                Market::PumpSwap => {
                    // Le cashback PumpSwap arrive en WSOL sur le compte WSOL du wallet, refermé ensuite.
                    let (wsol, token) = (key(WSOL_MINT)?, key(TOKEN_PROGRAM)?);
                    let ata = |owner: &Pubkey| pda(&[owner, &token, &wsol], ATA_PROGRAM);
                    let user_wsol = ata(user)?;
                    ixs.push(Instruction {
                        program: key(ATA_PROGRAM)?,
                        accounts: vec![
                            signer.clone(),
                            rw(user_wsol),
                            ro(*user),
                            ro(wsol),
                            ro(SYSTEM_PROGRAM),
                            ro(token),
                        ],
                        data: vec![1],
                    });
                    ixs.push(Instruction {
                        program,
                        accounts: vec![
                            signer.clone(),
                            rw(uva),
                            ro(wsol),
                            ro(token),
                            rw(ata(&uva)?),
                            rw(user_wsol),
                            ro(SYSTEM_PROGRAM),
                            ro(events),
                            ro(program),
                        ],
                        data: CLAIM_CASHBACK.to_vec(),
                    });
                    ixs.push(Instruction {
                        program: token,
                        accounts: vec![
                            rw(user_wsol),
                            rw(*user),
                            AccountMeta {
                                pubkey: *user,
                                signer: true,
                                writable: false,
                            },
                        ],
                        data: vec![9],
                    });
                }
            }
        }
        ixs.push(Instruction {
            program,
            accounts: vec![signer, rw(uva), ro(events), ro(program)],
            data: CLOSE.to_vec(),
        });
        Ok(ixs)
    };
    build().map_err(|_| Blocked::PumpRewards)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(fields: &[u64]) -> Vec<u8> {
        let mut d = USER_DISCRIMINATOR.to_vec();
        d.extend_from_slice(&[7; 32]); // user
        d.push(0); // needs_claim
        d.extend_from_slice(&fields[0].to_le_bytes()); // total_unclaimed_tokens
        d.extend_from_slice(&0u64.to_le_bytes()); // total_claimed_tokens
        d.extend_from_slice(&fields[1].to_le_bytes()); // current_sol_volume
        d.extend_from_slice(&0u64.to_le_bytes()); // last_update_timestamp
        d.push(0);
        for f in &fields[2..] {
            d.extend_from_slice(&f.to_le_bytes());
        }
        d
    }

    #[test]
    fn ferme_un_compteur_vide_et_reclame_le_cashback_avant() {
        let user = [3; 32];
        let empty = UserVolume::decode(&account(&[0, 0, 0, 0, 0, 0])).unwrap_or_default();
        let ixs = reclaim(Market::Curve, &user, &empty, false).unwrap_or_default();
        assert_eq!(ixs.len(), 1);
        assert_eq!(ixs[0].data, CLOSE.to_vec());
        // Cashback en attente (curve) : réclamé d'abord, dans la même transaction.
        let cb = UserVolume::decode(&account(&[0, 0, 500, 100, 0, 0])).unwrap_or_default();
        assert_eq!(cb.pending_cashback(), 400);
        let ixs = reclaim(Market::Curve, &user, &cb, false).unwrap_or_default();
        assert_eq!(
            ixs.iter().map(|i| i.data.clone()).collect::<Vec<_>>(),
            vec![CLAIM_CASHBACK.to_vec(), CLOSE.to_vec()]
        );
        // PumpSwap : WSOL ouvert, cashback, WSOL refermé, puis fermeture.
        let ixs = reclaim(Market::PumpSwap, &user, &cb, false).unwrap_or_default();
        assert_eq!(ixs.len(), 4);
        assert_eq!(ixs[3].data, CLOSE.to_vec());
    }

    #[test]
    fn refuse_de_perdre_des_recompenses() {
        let user = [3; 32];
        let unclaimed = UserVolume::decode(&account(&[42, 0, 0, 0, 0, 0])).unwrap_or_default();
        assert_eq!(
            reclaim(Market::Curve, &user, &unclaimed, false),
            Err(Blocked::PumpRewards)
        );
        // Volume du jour alors que le programme PUMP est actif : récompenses de demain.
        let today = UserVolume::decode(&account(&[0, 9_000, 0, 0, 0, 0])).unwrap_or_default();
        assert_eq!(
            reclaim(Market::Curve, &user, &today, true),
            Err(Blocked::PumpRewards)
        );
        assert!(reclaim(Market::Curve, &user, &today, false).is_ok()); // programme inactif : rien à perdre
        let stable = UserVolume::decode(&account(&[0, 0, 0, 0, 10, 0])).unwrap_or_default();
        assert_eq!(
            reclaim(Market::Curve, &user, &stable, false),
            Err(Blocked::StableCashback)
        );
    }

    #[test]
    fn programme_de_recompenses_inactif_si_dates_nulles() {
        let mut g = GLOBAL_DISCRIMINATOR.to_vec();
        g.extend_from_slice(&[0; 16]);
        assert_eq!(incentives_active(&g), Ok(false));
        let mut g = GLOBAL_DISCRIMINATOR.to_vec();
        g.extend_from_slice(&1_700_000_000u64.to_le_bytes());
        g.extend_from_slice(&1_800_000_000u64.to_le_bytes());
        assert_eq!(incentives_active(&g), Ok(true));
    }
}
