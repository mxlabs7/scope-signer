//! Briques Solana minimales, partagées par le signer et le moteur (sans dépendance au SDK Solana).
//!
//! Le signer ne signe que ce qu'il a LU et COMPRIS : il décode le message (legacy ou v0),
//! refuse les tables d'adresses (comptes invisibles hors ligne) et expose chaque instruction
//! avec ses vrais comptes. Testé contre des messages produits par @solana/web3.js.

use sha2::{Digest, Sha256};

pub type Pubkey = [u8; 32];

/// Taille max d'une transaction Solana.
pub const MAX_TX: usize = 1232;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    BadLength,
    /// Le message utilise des tables d'adresses : comptes non vérifiables hors ligne.
    LookupTables,
    UnknownVersion,
    BadAccountIndex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub program: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub required_signatures: u8,
    /// Comptes du message ; le premier est le payeur des frais.
    pub accounts: Vec<Pubkey>,
    pub instructions: Vec<Instruction>,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.0.len() < n {
            return Err(ParseError::Truncated);
        }
        let (h, r) = self.0.split_at(n);
        self.0 = r;
        Ok(h)
    }
    fn byte(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }
    /// Entier « compact-u16 » de Solana (1 à 3 octets).
    fn compact(&mut self) -> Result<usize, ParseError> {
        let mut value = 0usize;
        for i in 0..3 {
            let b = self.byte()?;
            value |= ((b & 0x7f) as usize) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ParseError::BadLength)
    }
}

/// Décode un message de transaction (la partie que l'on signe).
pub fn parse_message(bytes: &[u8]) -> Result<Message, ParseError> {
    if bytes.len() > MAX_TX {
        return Err(ParseError::BadLength);
    }
    let mut r = Reader(bytes);
    let first = *bytes.first().ok_or(ParseError::Truncated)?;
    let v0 = first & 0x80 != 0;
    if v0 {
        if first & 0x7f != 0 {
            return Err(ParseError::UnknownVersion);
        }
        r.byte()?;
    }
    let required_signatures = r.byte()?;
    r.take(2)?; // comptes en lecture seule (signés / non signés) : sans incidence sur nos règles
    let n_accounts = r.compact()?;
    let mut accounts = Vec::with_capacity(n_accounts);
    for _ in 0..n_accounts {
        accounts.push(r.take(32)?.try_into().map_err(|_| ParseError::Truncated)?);
    }
    r.take(32)?; // blockhash récent
    let n_ix = r.compact()?;
    let mut instructions = Vec::with_capacity(n_ix);
    for _ in 0..n_ix {
        let account_at = |i: u8| {
            accounts
                .get(i as usize)
                .copied()
                .ok_or(ParseError::BadAccountIndex)
        };
        let program = account_at(r.byte()?)?;
        let n = r.compact()?;
        let idx = r.take(n)?;
        let ix_accounts = idx
            .iter()
            .map(|i| account_at(*i))
            .collect::<Result<Vec<_>, _>>()?;
        let len = r.compact()?;
        let data = r.take(len)?.to_vec();
        instructions.push(Instruction {
            program,
            accounts: ix_accounts,
            data,
        });
    }
    if v0 && r.compact()? != 0 {
        return Err(ParseError::LookupTables);
    }
    if !r.0.is_empty() {
        return Err(ParseError::BadLength);
    }
    if required_signatures == 0 || accounts.is_empty() {
        return Err(ParseError::BadLength);
    }
    Ok(Message {
        required_signatures,
        accounts,
        instructions,
    })
}

/// Décode une adresse base58 (32 octets).
pub fn pubkey(b58: &str) -> Option<Pubkey> {
    bs58_decode(b58)?.try_into().ok()
}

fn bs58_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for b in out.iter_mut().rev() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    Some([vec![0u8; zeros], out].concat())
}

/// Adresse dérivée d'un programme (PDA) : comme `PublicKey.findProgramAddressSync`.
pub fn find_program_address(seeds: &[&[u8]], program: &Pubkey) -> Option<Pubkey> {
    find_program_address_bump(seeds, program).map(|(k, _)| k)
}

/// Adresses déjà calculées : une même adresse (comptes globaux, compteur d'un wallet, courbe du coin en
/// cours) sert plusieurs fois par transaction ; chaque calcul coûte des dizaines de µs. Mémoire bornée.
type PdaCache = std::sync::RwLock<std::collections::HashMap<Vec<u8>, (Pubkey, u8)>>;
static PDA_CACHE: std::sync::LazyLock<PdaCache> = std::sync::LazyLock::new(Default::default);
const PDA_CACHE_MAX: usize = 50_000;

/// Comme `find_program_address`, avec le « bump » trouvé (255 = trouvé du premier coup). Un programme
/// qui recalcule l'adresse paie ~1 500 unités de calcul par essai : 255 − bump essais en plus.
pub fn find_program_address_bump(seeds: &[&[u8]], program: &Pubkey) -> Option<(Pubkey, u8)> {
    let mut key = program.to_vec();
    for s in seeds {
        key.push(u8::try_from(s.len()).unwrap_or(u8::MAX));
        key.extend_from_slice(s);
    }
    if let Ok(cache) = PDA_CACHE.read()
        && let Some(hit) = cache.get(&key)
    {
        return Some(*hit);
    }
    let found = search_program_address(seeds, program)?;
    if let Ok(mut cache) = PDA_CACHE.write() {
        if cache.len() >= PDA_CACHE_MAX {
            cache.clear();
        }
        cache.insert(key, found);
    }
    Some(found)
}

fn search_program_address(seeds: &[&[u8]], program: &Pubkey) -> Option<(Pubkey, u8)> {
    for bump in (0..=255u8).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program);
        h.update(b"ProgramDerivedAddress");
        let candidate: Pubkey = h.finalize().into();
        // Une PDA ne doit PAS être une clé publique valide (hors de la courbe).
        if curve25519_dalek::edwards::CompressedEdwardsY(candidate)
            .decompress()
            .is_none()
        {
            return Some((candidate, bump));
        }
    }
    None
}

pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";

/// Compte de tokens associé (ATA) d'un wallet pour un mint.
pub fn associated_token_address(
    wallet: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Option<Pubkey> {
    find_program_address(&[wallet, token_program, mint], &pubkey(ATA_PROGRAM)?)
}

// ---------- Construction de transactions ----------

/// Compte d'une instruction à construire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub signer: bool,
    pub writable: bool,
}

/// Instruction à construire (pendant de `TransactionInstruction` de @solana/web3.js).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ix {
    pub program: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

fn compact(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            return;
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CompileError {
    TooManyAccounts,
    TooLarge,
}

/// Compile un message « legacy », octet pour octet comme `TransactionMessage.compileToLegacyMessage()` :
/// payeur en premier, puis signataires en écriture, signataires en lecture, comptes en écriture,
/// comptes en lecture — chaque groupe dans l'ordre d'apparition (programme avant ses comptes).
pub fn compile_legacy(
    payer: &Pubkey,
    ixs: &[Ix],
    blockhash: &[u8; 32],
) -> Result<Vec<u8>, CompileError> {
    // (clé, signataire, écriture) dans l'ordre d'insertion, en fusionnant les drapeaux.
    let mut keys: Vec<(Pubkey, bool, bool)> = vec![(*payer, true, true)];
    let mut upsert =
        |k: Pubkey, signer: bool, writable: bool| match keys.iter_mut().find(|e| e.0 == k) {
            Some(e) => {
                e.1 |= signer;
                e.2 |= writable;
            }
            None => keys.push((k, signer, writable)),
        };
    for ix in ixs {
        upsert(ix.program, false, false);
        for a in &ix.accounts {
            upsert(a.pubkey, a.signer, a.writable);
        }
    }
    let group = |s: bool, w: bool| {
        keys.iter()
            .filter(move |e| e.1 == s && e.2 == w)
            .map(|e| e.0)
    };
    let ordered: Vec<Pubkey> = std::iter::once(*payer)
        .chain(group(true, true).filter(|k| k != payer))
        .chain(group(true, false))
        .chain(group(false, true))
        .chain(group(false, false))
        .collect();
    if ordered.len() > 255 {
        return Err(CompileError::TooManyAccounts);
    }
    let n_signed = keys.iter().filter(|e| e.1).count() as u8;
    let ro_signed = keys.iter().filter(|e| e.1 && !e.2).count() as u8;
    let ro_unsigned = keys.iter().filter(|e| !e.1 && !e.2).count() as u8;
    let index = |k: &Pubkey| ordered.iter().position(|x| x == k).unwrap_or(0) as u8;

    let mut out = vec![n_signed, ro_signed, ro_unsigned];
    compact(&mut out, ordered.len());
    for k in &ordered {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(blockhash);
    compact(&mut out, ixs.len());
    for ix in ixs {
        out.push(index(&ix.program));
        compact(&mut out, ix.accounts.len());
        out.extend(ix.accounts.iter().map(|a| index(&a.pubkey)));
        compact(&mut out, ix.data.len());
        out.extend_from_slice(&ix.data);
    }
    if out.len() + 1 + 64 > MAX_TX {
        return Err(CompileError::TooLarge);
    }
    Ok(out)
}

/// Transaction prête à l'envoi : signatures puis message.
pub fn transaction(signatures: &[[u8; 64]], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 64 * signatures.len() + message.len());
    compact(&mut out, signatures.len());
    for s in signatures {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(message);
    out
}

/// Encode en base58 (adresses, signatures).
pub fn bs58_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    std::iter::repeat_n('1', zeros)
        .chain(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char))
        .collect()
}

/// Programme et instructions du budget de calcul.
pub const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";

pub fn set_compute_unit_limit(units: u32) -> Option<Ix> {
    let mut data = vec![2];
    data.extend_from_slice(&units.to_le_bytes());
    Some(Ix {
        program: pubkey(COMPUTE_BUDGET)?,
        accounts: vec![],
        data,
    })
}

pub fn set_compute_unit_price(micro_lamports: u64) -> Option<Ix> {
    let mut data = vec![3];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Some(Ix {
        program: pubkey(COMPUTE_BUDGET)?,
        accounts: vec![],
        data,
    })
}

/// Transfert de SOL (System Program).
pub fn transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Ix {
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&lamports.to_le_bytes());
    Ix {
        program: [0; 32],
        accounts: vec![
            AccountMeta {
                pubkey: *from,
                signer: true,
                writable: true,
            },
            AccountMeta {
                pubkey: *to,
                signer: false,
                writable: true,
            },
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
            .collect()
    }

    // Vecteurs produits par @solana/web3.js (wallet = Keypair.fromSeed(7×32)).
    const WALLET: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const ATA_WSOL: &str = "3da2d73b1075ea44155428ffe126b4ad17c710d021071112073e514067838fc1";
    const FEE: &str = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
    const LEGACY: &str = "01000406ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22cfd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f6180306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a400000000156e0f693665acf44db1568bf175baa5189cb97f5d2ff3b655d2bb6fd6d18b0069b8857feab8184fb687f634618c035dac439dc1aeb3b5598a0f000000000010000000000000000000000000000000000000000000000000000000000000000850f2d6e02a47af824d09ab69dc42d70cb28cbfa249fb7ee57b9d256c12762ef0302000502c0d40100030200041838fc74089edfcd5f40420f00000000000100000000000000050200010c020000001027000000000000";

    fn arr(s: &str) -> Pubkey {
        unhex(s).try_into().unwrap_or([0; 32])
    }

    #[test]
    fn derive_l_ata_comme_web3js() {
        let ata = associated_token_address(
            &arr(WALLET),
            &pubkey(WSOL_MINT).unwrap_or([0; 32]),
            &pubkey(TOKEN_PROGRAM).unwrap_or([0; 32]),
        );
        assert_eq!(ata, Some(arr(ATA_WSOL)));
    }

    /// Mêmes instructions que le vecteur LEGACY (produit par @solana/web3.js) : octets identiques.
    #[test]
    fn compile_exactement_comme_web3js() -> Result<(), CompileError> {
        let wallet = arr(WALLET);
        let fee = arr(FEE);
        let wsol = pubkey(WSOL_MINT).unwrap_or([0; 32]);
        let pump = pubkey("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P").unwrap_or([0; 32]);
        let ixs = vec![
            set_compute_unit_limit(120_000).unwrap_or_else(|| unreachable!()),
            Ix {
                program: pump,
                accounts: vec![
                    AccountMeta {
                        pubkey: wallet,
                        signer: true,
                        writable: true,
                    },
                    AccountMeta {
                        pubkey: wsol,
                        signer: false,
                        writable: false,
                    },
                ],
                data: unhex("38fc74089edfcd5f40420f00000000000100000000000000"),
            },
            transfer(&wallet, &fee, 10_000),
        ];
        let blockhash: [u8; 32] = bs58_decode("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin")
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0; 32]);
        assert_eq!(compile_legacy(&wallet, &ixs, &blockhash)?, unhex(LEGACY));
        Ok(())
    }

    #[test]
    fn base58_aller_retour() {
        for bytes in [
            vec![],
            vec![0, 0, 1],
            vec![255; 32],
            (0..64).collect::<Vec<u8>>(),
        ] {
            assert_eq!(bs58_decode(&bs58_encode(&bytes)), Some(bytes));
        }
        assert_eq!(bs58_encode(&[0; 32]), "11111111111111111111111111111111");
    }

    #[test]
    fn decode_base58() {
        assert_eq!(pubkey("11111111111111111111111111111111"), Some([0; 32]));
        assert!(pubkey("0OIl").is_none());
    }

    #[test]
    fn lit_un_message_legacy_et_v0() -> Result<(), ParseError> {
        let legacy = parse_message(&unhex(LEGACY))?;
        // v0 = même contenu, préfixe de version et zéro table d'adresses.
        let v0_hex = format!("80{LEGACY}00");
        let v0 = parse_message(&unhex(&v0_hex))?;
        assert_eq!(legacy, v0);
        assert_eq!(legacy.accounts[0], arr(WALLET));
        assert_eq!(legacy.required_signatures, 1);
        assert_eq!(legacy.instructions.len(), 3);
        let transfer = &legacy.instructions[2];
        assert_eq!(transfer.program, [0; 32]);
        assert_eq!(transfer.accounts, vec![arr(WALLET), arr(FEE)]);
        assert_eq!(transfer.data, unhex("020000001027000000000000"));
        Ok(())
    }

    #[test]
    fn refuse_les_tables_d_adresses_et_les_messages_abimes() {
        let with_lut = format!("80{LEGACY}01");
        assert!(parse_message(&unhex(&with_lut)).is_err());
        let full = unhex(LEGACY);
        for cut in [0, 1, 10, 100, full.len() - 1] {
            assert!(parse_message(&full[..cut]).is_err(), "coupé à {cut}");
        }
        let mut extra = full.clone();
        extra.push(0);
        assert_eq!(parse_message(&extra), Err(ParseError::BadLength));
        let mut bad_index = full.clone();
        // Instruction pointant un compte inexistant.
        if let Some(pos) = bad_index.windows(2).position(|w| w == [0x03, 0x02]) {
            bad_index[pos] = 0x30;
        }
        assert!(parse_message(&bad_index).is_err());
    }

    #[test]
    fn aucune_panique_sur_entree_arbitraire() {
        let base = unhex(LEGACY);
        let mut x: u64 = 0xDEAD_BEEF_1234_5678;
        for _ in 0..100_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut m = base.clone();
            let pos = (x as usize) % m.len();
            m[pos] ^= (x >> 40) as u8;
            if x.is_multiple_of(7) {
                m.truncate(pos);
            }
            let _ = parse_message(&m);
        }
    }
}
