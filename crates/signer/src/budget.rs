//! Budget de calcul d'une transaction : lecture des instructions ComputeBudget et frais de priorité.
//! Commun aux trades et aux retraits : un moteur compromis ne doit pas pouvoir brûler le SOL d'un
//! wallet en frais de priorité (ils partent aux validateurs : perte pour l'utilisateur).

use scope_solana::Pubkey;

pub const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
/// Limite de calcul appliquée par Solana quand la transaction n'en fixe pas (pire cas).
const DEFAULT_CU_LIMIT: u64 = 1_400_000;

/// Limite et prix lus dans les instructions ComputeBudget d'une transaction.
#[derive(Default)]
pub struct Budget {
    limit: Option<u64>,
    price: u64,
}

impl Budget {
    /// Lit une instruction ComputeBudget. Seuls SetComputeUnitLimit (2) et SetComputeUnitPrice (3)
    /// sont acceptés ; un doublon est refusé (ambigu). `Err` = instruction interdite.
    pub fn read(&mut self, data: &[u8]) -> Result<(), ()> {
        match (data.first(), data.len()) {
            (Some(2), 5) if self.limit.is_none() => {
                self.limit = Some(u64::from(u32::from_le_bytes(
                    data[1..5].try_into().map_err(|_| ())?,
                )));
                Ok(())
            }
            (Some(3), 9) if self.price == 0 => {
                self.price = u64::from_le_bytes(data[1..9].try_into().map_err(|_| ())?);
                Ok(())
            }
            _ => Err(()),
        }
    }

    /// Frais de priorité maximum (lamports) : limite × prix (micro-lamports), arrondi au-dessus.
    pub fn priority_lamports(&self) -> u64 {
        let p = (u128::from(self.limit.unwrap_or(DEFAULT_CU_LIMIT)) * u128::from(self.price))
            .div_ceil(1_000_000);
        u64::try_from(p).unwrap_or(u64::MAX)
    }
}

pub fn program() -> Option<Pubkey> {
    scope_solana::pubkey(COMPUTE_BUDGET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calcule_les_frais_de_priorite() {
        let mut b = Budget::default();
        assert_eq!(b.read(&[2, 0xa0, 0x86, 0x01, 0x00]), Ok(())); // 100 000 CU
        let mut price = vec![3];
        price.extend_from_slice(&1_000_000u64.to_le_bytes());
        assert_eq!(b.read(&price), Ok(()));
        assert_eq!(b.priority_lamports(), 100_000);
        // Doublon (deuxième prix plus élevé) : refusé, ambigu.
        assert_eq!(b.read(&price), Err(()));
        // Autres opérations (ex. RequestHeapFrame = 1) : refusées.
        assert_eq!(Budget::default().read(&[1, 0, 0, 0, 0]), Err(()));
        // Prix sans limite : calculé sur la limite maximale de Solana.
        let mut b = Budget::default();
        assert_eq!(b.read(&price), Ok(()));
        assert_eq!(b.priority_lamports(), 1_400_000);
    }
}
