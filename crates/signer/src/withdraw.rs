//! Retraits de SOL : ce qu'une transaction de retrait a le droit de faire.
//!
//! Le retrait est validé par une PASSKEY du compte, sur un défi qui couvre le wallet source, l'adresse
//! de destination et le montant exact (voir `factors::verify_withdraw`). Ici on vérifie que la
//! transaction fait EXACTEMENT ce que l'utilisateur a validé, et rien d'autre :
//! - le wallet est le seul signataire et paie les frais ;
//! - une seule instruction de transfert : du wallet vers la destination, du montant validé ;
//! - en plus, seulement le budget de calcul, avec des frais de priorité plafonnés (un moteur compromis
//!   ne peut pas brûler le SOL du wallet en frais).

use scope_solana::{Message, Pubkey};

use crate::budget::{self, Budget};

const SYSTEM_PROGRAM: Pubkey = [0; 32];
/// Plafond des frais de priorité d'un retrait (0,0001 SOL) : largement assez pour passer en congestion.
pub const MAX_PRIORITY_LAMPORTS: u64 = 100_000;

#[derive(Debug, PartialEq, Eq)]
pub enum WithdrawViolation {
    NotSoleSigner,
    WrongFeePayer,
    /// Instruction autre que le budget de calcul et LE transfert.
    InstructionNotAllowed,
    /// Transfert absent, en double, ou différent de ce qui a été validé (source, destination, montant).
    TransferMismatch,
    PriorityTooHigh(u64),
    ZeroAmount,
}

pub fn check_withdraw(
    wallet: &Pubkey,
    to: &Pubkey,
    lamports: u64,
    msg: &Message,
) -> Result<(), WithdrawViolation> {
    use WithdrawViolation::*;
    if lamports == 0 {
        return Err(ZeroAmount);
    }
    if msg.required_signatures != 1 {
        return Err(NotSoleSigner);
    }
    if msg.accounts.first() != Some(wallet) {
        return Err(WrongFeePayer);
    }
    let compute_budget = budget::program().ok_or(InstructionNotAllowed)?;
    let (mut b, mut transfers) = (Budget::default(), 0usize);
    for ix in &msg.instructions {
        let d = &ix.data;
        if ix.program == compute_budget {
            b.read(d).map_err(|()| InstructionNotAllowed)?;
        } else if ix.program == SYSTEM_PROGRAM {
            if d.len() != 12 || d[..4] != [2, 0, 0, 0] {
                return Err(InstructionNotAllowed);
            }
            let amount = u64::from_le_bytes(d[4..12].try_into().map_err(|_| TransferMismatch)?);
            if ix.accounts.first() != Some(wallet)
                || ix.accounts.get(1) != Some(to)
                || amount != lamports
            {
                return Err(TransferMismatch);
            }
            transfers += 1;
        } else {
            return Err(InstructionNotAllowed);
        }
    }
    if transfers != 1 {
        return Err(TransferMismatch);
    }
    let priority = b.priority_lamports();
    if priority > MAX_PRIORITY_LAMPORTS {
        return Err(PriorityTooHigh(priority));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use scope_solana::{
        compile_legacy, parse_message, set_compute_unit_limit, set_compute_unit_price, transfer,
    };

    const W: Pubkey = [0xaa; 32];
    const TO: Pubkey = [0xbb; 32];
    const SOL: u64 = 1_000_000_000;

    fn msg(ixs: &[scope_solana::Ix]) -> Message {
        let m = compile_legacy(&W, ixs, &[9; 32]).unwrap_or_else(|e| panic!("{e:?}"));
        parse_message(&m).unwrap_or_else(|e| panic!("{e:?}"))
    }

    fn budget(limit: u32, price: u64) -> Vec<scope_solana::Ix> {
        vec![
            set_compute_unit_limit(limit).unwrap_or_else(|| panic!("cu")),
            set_compute_unit_price(price).unwrap_or_else(|| panic!("prix")),
        ]
    }

    #[test]
    fn accepte_exactement_le_retrait_valide() {
        let mut ixs = budget(1_000, 1_000_000);
        ixs.push(transfer(&W, &TO, SOL));
        assert_eq!(check_withdraw(&W, &TO, SOL, &msg(&ixs)), Ok(()));
        // Sans budget de calcul aussi.
        assert_eq!(
            check_withdraw(&W, &TO, SOL, &msg(&[transfer(&W, &TO, SOL)])),
            Ok(())
        );
    }

    #[test]
    fn refuse_un_autre_montant_une_autre_destination_ou_un_second_transfert() {
        use WithdrawViolation::*;
        let thief = [0x66; 32];
        assert_eq!(
            check_withdraw(&W, &TO, SOL, &msg(&[transfer(&W, &TO, SOL + 1)])),
            Err(TransferMismatch)
        );
        assert_eq!(
            check_withdraw(&W, &TO, SOL, &msg(&[transfer(&W, &thief, SOL)])),
            Err(TransferMismatch)
        );
        assert_eq!(
            check_withdraw(
                &W,
                &TO,
                SOL,
                &msg(&[transfer(&W, &TO, SOL), transfer(&W, &thief, 1)])
            ),
            Err(TransferMismatch)
        );
        assert_eq!(
            check_withdraw(
                &W,
                &TO,
                SOL,
                &msg(&[transfer(&W, &TO, SOL), transfer(&W, &TO, SOL)])
            ),
            Err(TransferMismatch)
        );
        assert_eq!(
            check_withdraw(&W, &TO, SOL, &msg(&budget(1_000, 1))),
            Err(TransferMismatch)
        );
        assert_eq!(
            check_withdraw(&W, &TO, 0, &msg(&[transfer(&W, &TO, 0)])),
            Err(ZeroAmount)
        );
    }

    #[test]
    fn refuse_toute_autre_instruction() {
        let token = scope_solana::Ix {
            program: scope_solana::pubkey(scope_solana::TOKEN_PROGRAM).unwrap_or([0; 32]),
            accounts: vec![],
            data: vec![9],
        };
        assert_eq!(
            check_withdraw(&W, &TO, SOL, &msg(&[transfer(&W, &TO, SOL), token])),
            Err(WithdrawViolation::InstructionNotAllowed)
        );
    }

    #[test]
    fn plafonne_les_frais_de_priorite() {
        // 1 000 000 CU × 1 000 000 µlamports = 1 SOL de frais : refusé.
        let mut ixs = budget(1_000_000, 1_000_000);
        ixs.push(transfer(&W, &TO, SOL));
        assert!(matches!(
            check_withdraw(&W, &TO, SOL, &msg(&ixs)),
            Err(WithdrawViolation::PriorityTooHigh(_))
        ));
        // Prix seul sans limite : calculé sur la limite maximale de Solana.
        let ixs = vec![
            set_compute_unit_price(1_000_000).unwrap_or_else(|| panic!()),
            transfer(&W, &TO, SOL),
        ];
        assert!(matches!(
            check_withdraw(&W, &TO, SOL, &msg(&ixs)),
            Err(WithdrawViolation::PriorityTooHigh(_))
        ));
    }
}
