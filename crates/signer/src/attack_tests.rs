//! Attaque du signer : des milliers de transactions PIÉGÉES, toutes doivent être refusées.
//!
//! Point de départ : les transactions RÉELLES du moteur (vrais coins et pools capturés sur mainnet,
//! courbe + PumpSwap, achats + ventes, retraits), vérifiées acceptées. Puis, au hasard (graine fixe,
//! reproductible), 1 à 3 pièges par transaction, chacun dangereux à coup sûr : vol, détournement,
//! prise de contrôle d'un compte, mauvaise fee, frais gonflés… Le signer doit TOUT refuser.

use ed25519_dalek::Signer as _;
use scope_pump::amm::{GlobalConfig, Pool, Swap};
use scope_pump::{BondingCurve, Global, Trade};
use scope_solana::{
    self as solana, AccountMeta, Ix, Pubkey, compile_legacy, parse_message, set_compute_unit_limit,
    set_compute_unit_price, transfer,
};

use super::testing::authority;
use super::{Rules, TOKEN_2022};
use crate::withdraw::check_withdraw;

const W: Pubkey = [0xaa; 32];
const THIEF: Pubkey = [0x66; 32];
const SOL: u64 = 1_000_000_000;
const RUNS: usize = 5_000;

fn rules() -> Rules {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../infra/rules/rules.json");
    let j = std::fs::read(path).unwrap_or_default();
    let sig = authority().sign(&j).to_bytes();
    Rules::load(&j, &sig, &authority().verifying_key()).unwrap_or_else(|e| panic!("{e:?}"))
}

fn k(s: &str) -> Pubkey {
    solana::pubkey(s).unwrap_or_else(|| panic!("adresse : {s}"))
}

fn b64(v: &serde_json::Value) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap_or_default())
        .unwrap_or_default()
}

fn fixtures(sub: &str) -> Vec<serde_json::Value> {
    let dir = format!(
        "{}/../pump/tests/fixtures/{sub}",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .map(|d| d.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default();
    paths.retain(|p| p.extension().is_some_and(|x| x == "json"));
    paths.sort(); // ordre stable : test reproductible
    paths
        .iter()
        .filter_map(|p| serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok())
        .collect()
}

/// Une transaction de base, VALIDE, et ce qu'il faut savoir pour la piéger.
#[derive(Clone)]
struct Base {
    kind: Kind,
    ixs: Vec<Ix>,
    /// Position de l'instruction de trade, du compte utilisateur et des comptes de tokens.
    trade: usize,
    user_index: usize,
    token_accounts: Vec<usize>,
    /// SOL attendu (ventes) / montant (retraits).
    expected: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Buy,
    Sell,
    Withdraw,
}

fn budget() -> Vec<Ix> {
    vec![
        set_compute_unit_limit(250_000).unwrap_or_else(|| panic!()),
        set_compute_unit_price(100_000).unwrap_or_else(|| panic!()),
    ]
}

/// Comme le moteur : budget + instructions du trade + fee Scope + tip.
fn trade_base(
    r: &Rules,
    kind: Kind,
    trade_ixs: Vec<Ix>,
    fee: u64,
    expected: u64,
    user_index: usize,
    token_accounts: Vec<usize>,
) -> Base {
    let mut ixs = budget();
    let program_ixs: Vec<Pubkey> = r.ixs.iter().map(|x| x.program).collect();
    let offset = ixs.len();
    let trade = offset
        + trade_ixs
            .iter()
            .position(|ix| program_ixs.contains(&ix.program))
            .unwrap_or_else(|| panic!("pas d'instruction de trade"));
    ixs.extend(trade_ixs);
    ixs.push(transfer(&W, &r.fee_wallet, fee));
    ixs.push(transfer(
        &W,
        r.tips.iter().next().unwrap_or(&[0; 32]),
        10_000,
    ));
    Base {
        kind,
        ixs,
        trade,
        user_index,
        token_accounts,
        expected,
    }
}

fn bases(r: &Rules) -> Vec<Base> {
    let mut out = Vec::new();
    let ok = |x: Result<Ix, scope_pump::PumpError>| x.unwrap_or_else(|e| panic!("{e:?}"));
    for fx in fixtures("") {
        let global = Global::decode(&b64(&fx["accounts"]["global"]["data"]))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let curve = BondingCurve::decode(&b64(&fx["accounts"]["bonding_curve"]["data"]))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let t = Trade {
            global: &global,
            curve: &curve,
            mint: k(fx["mint"].as_str().unwrap_or_default()),
            token_program: k(fx["token_program"].as_str().unwrap_or_default()),
            user: W,
            fee_recipient_index: 1,
            buyback_index: 2,
        };
        out.push(trade_base(
            r,
            Kind::Buy,
            vec![ok(t.create_user_ata()), ok(t.buy_exact_sol_in(SOL, 1))],
            SOL / 100,
            0,
            6,
            vec![5],
        ));
        out.push(trade_base(
            r,
            Kind::Sell,
            vec![ok(t.sell(1_000, SOL / 2)), ok(t.close_user_ata())],
            SOL / 100,
            SOL,
            6,
            vec![5],
        ));
    }
    for fx in fixtures("amm") {
        let config = GlobalConfig::decode(&b64(&fx["accounts"]["global_config"]["data"]))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let pool =
            Pool::decode(&b64(&fx["accounts"]["pool"]["data"])).unwrap_or_else(|e| panic!("{e:?}"));
        let s = Swap {
            config: &config,
            pool: &pool,
            pool_key: k(fx["pool"].as_str().unwrap_or_default()),
            base_token_program: k(fx["base_token_program"].as_str().unwrap_or_default()),
            user: W,
            fee_recipient_index: 4,
            buyback_index: 7,
        };
        let mut buy = s.open_wsol(SOL).unwrap_or_else(|e| panic!("{e:?}"));
        buy.extend([
            ok(s.create_base_ata()),
            ok(s.buy_exact_quote_in(SOL, 1)),
            ok(s.close_wsol()),
        ]);
        out.push(trade_base(r, Kind::Buy, buy, SOL / 100, 0, 1, vec![5, 6]));
        let sell = vec![
            s.open_wsol(0).unwrap_or_default().remove(0),
            ok(s.sell(1_000, SOL / 2)),
            ok(s.close_wsol()),
            ok(s.close_base_ata()),
        ];
        out.push(trade_base(
            r,
            Kind::Sell,
            sell,
            SOL / 100,
            SOL,
            1,
            vec![5, 6],
        ));
    }
    // Retrait : budget fixe + un transfert.
    let mut w = vec![
        set_compute_unit_limit(1_000).unwrap_or_else(|| panic!()),
        set_compute_unit_price(1_000_000).unwrap_or_else(|| panic!()),
    ];
    w.push(transfer(&W, &[0xbb; 32], SOL));
    out.push(Base {
        kind: Kind::Withdraw,
        ixs: w,
        trade: 2,
        user_index: 0,
        token_accounts: vec![],
        expected: SOL,
    });
    out
}

/// Verdict du signer sur une transaction (payeur, instructions).
fn accepted(r: &Rules, b: &Base, payer: &Pubkey, ixs: &[Ix]) -> bool {
    let Ok(raw) = compile_legacy(payer, ixs, &[9; 32]) else {
        return false;
    };
    let Ok(msg) = parse_message(&raw) else {
        return false;
    };
    match b.kind {
        Kind::Withdraw => check_withdraw(&W, &[0xbb; 32], b.expected, &msg).is_ok(),
        Kind::Buy => r.check_trade(&W, &msg, 0).is_ok(),
        Kind::Sell => r.check_trade(&W, &msg, b.expected).is_ok(),
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn key(&mut self) -> Pubkey {
        let mut k = [0u8; 32];
        for c in k.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        k
    }
}

fn rw(pubkey: Pubkey) -> AccountMeta {
    AccountMeta {
        pubkey,
        signer: false,
        writable: true,
    }
}

fn signer_meta(pubkey: Pubkey) -> AccountMeta {
    AccountMeta {
        pubkey,
        signer: true,
        writable: true,
    }
}

/// Position actuelle de l'instruction de trade (les pièges insèrent des instructions avant elle).
fn find_trade(b: &Base, ixs: &[Ix]) -> Option<usize> {
    let orig = &b.ixs[b.trade];
    if b.kind == Kind::Withdraw {
        return ixs.iter().position(|ix| ix == orig);
    }
    ixs.iter()
        .position(|ix| ix.program == orig.program && ix.data.get(..8) == orig.data.get(..8))
}

/// Les pièges. Chacun rend la transaction dangereuse À COUP SÛR.
const TRAPS: &[&str] = &[
    "transfert de vol",
    "compte de tokens détourné",
    "trade pour un autre utilisateur",
    "programme inconnu",
    "instruction token dangereuse",
    "instruction système dangereuse",
    "fee modifiée",
    "fee supprimée",
    "montant du trade gonflé",
    "second signataire",
    "autre payeur",
    "tip au-delà du plafond",
    "priorité au-delà du plafond",
    "instruction de trade inconnue",
    "retrait détourné",
];

/// Applique le piège `t` ; `None` si le piège ne s'applique pas à cette base.
fn trap(
    t: usize,
    b: &Base,
    ixs: &mut Vec<Ix>,
    payer: &mut Pubkey,
    rng: &mut Rng,
    r: &Rules,
) -> Option<()> {
    let is_trade = b.kind != Kind::Withdraw;
    let token_programs = [k(solana::TOKEN_PROGRAM), k(TOKEN_2022)];
    let ti = find_trade(b, ixs);
    match t {
        0 => {
            let to = if rng.below(2) == 0 { THIEF } else { rng.key() };
            let at = rng.below(ixs.len() + 1);
            ixs.insert(at, transfer(&W, &to, 1 + rng.next() % SOL));
        }
        1 if is_trade => {
            let acc = b.token_accounts[rng.below(b.token_accounts.len())];
            ixs[ti?].accounts[acc].pubkey = rng.key();
        }
        2 if is_trade => {
            ixs[ti?].accounts[b.user_index].pubkey = THIEF;
        }
        3 => {
            let at = rng.below(ixs.len() + 1);
            ixs.insert(
                at,
                Ix {
                    program: rng.key(),
                    accounts: vec![rw(W)],
                    data: vec![1, 2, 3],
                },
            );
        }
        4 => {
            // Approve (4), SetAuthority (6), Transfer (3), Burn (8), TransferChecked (12), Close vers le voleur.
            let ata = rng.key();
            let (data, accounts) = match rng.below(6) {
                0 => (
                    vec![4, 1, 0, 0, 0, 0, 0, 0, 0],
                    vec![rw(ata), rw(THIEF), signer_meta(W)],
                ),
                1 => (
                    [vec![6, 2, 1], THIEF.to_vec()].concat(),
                    vec![rw(ata), signer_meta(W)],
                ),
                2 => (
                    vec![3, 1, 0, 0, 0, 0, 0, 0, 0],
                    vec![rw(ata), rw(THIEF), signer_meta(W)],
                ),
                3 => (
                    vec![8, 1, 0, 0, 0, 0, 0, 0, 0],
                    vec![rw(ata), rw(rng.key()), signer_meta(W)],
                ),
                4 => (
                    vec![12, 1, 0, 0, 0, 0, 0, 0, 0, 6],
                    vec![rw(ata), rw(rng.key()), rw(THIEF), signer_meta(W)],
                ),
                _ => (vec![9], vec![rw(ata), rw(THIEF), signer_meta(W)]),
            };
            let program = token_programs[rng.below(2)];
            let at = rng.below(ixs.len() + 1);
            ixs.insert(
                at,
                Ix {
                    program,
                    accounts,
                    data,
                },
            );
        }
        5 => {
            // Assign (1), CreateAccount (0), Allocate (8), TransferWithSeed (11), AdvanceNonce (4).
            let (data, accounts) = match rng.below(5) {
                0 => (
                    [vec![1, 0, 0, 0], THIEF.to_vec()].concat(),
                    vec![signer_meta(W)],
                ),
                1 => (
                    [vec![0, 0, 0, 0], vec![0; 16], THIEF.to_vec()].concat(),
                    vec![signer_meta(W), signer_meta(W)],
                ),
                2 => (
                    vec![8, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                    vec![signer_meta(W)],
                ),
                3 => (
                    [vec![11, 0, 0, 0], vec![1; 8], vec![0; 8], THIEF.to_vec()].concat(),
                    vec![rw(W), signer_meta(W), rw(THIEF)],
                ),
                _ => (vec![4, 0, 0, 0], vec![rw(rng.key()), signer_meta(W)]),
            };
            let at = rng.below(ixs.len() + 1);
            ixs.insert(
                at,
                Ix {
                    program: [0; 32],
                    accounts,
                    data,
                },
            );
        }
        6 if is_trade => {
            // Fee : à la vente, seule une fee PLUS GROSSE est dangereuse (la borne basse est légale).
            let fee_ix = ixs.iter_mut().find(|ix| {
                ix.program == [0; 32]
                    && ix.accounts.get(1).is_some_and(|a| a.pubkey == r.fee_wallet)
            })?;
            let amount = u64::from_le_bytes(fee_ix.data[4..12].try_into().ok()?);
            let delta = 1 + rng.next() % (SOL / 10);
            let new = if b.kind == Kind::Buy && rng.below(2) == 0 {
                amount.checked_sub(delta)?
            } else {
                amount + delta
            };
            fee_ix.data[4..12].copy_from_slice(&new.to_le_bytes());
        }
        7 if is_trade => {
            ixs.retain(|ix| {
                !(ix.program == [0; 32]
                    && ix.accounts.get(1).is_some_and(|a| a.pubkey == r.fee_wallet))
            });
        }
        8 if is_trade => {
            // Achat : SOL dépensé ×2 sans la fee qui va avec. Vente : minimum garanti au-dessus de l'attendu.
            let d = &mut ixs[ti?].data;
            let (off, v) = if b.kind == Kind::Buy {
                (8, 2 * SOL)
            } else {
                (16, 2 * b.expected)
            };
            d[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        9 => {
            let i = rng.below(ixs.len());
            ixs[i].accounts.push(signer_meta(rng.key()));
        }
        10 => *payer = THIEF,
        11 if is_trade => {
            let tip = *r.tips.iter().next()?;
            ixs.push(transfer(&W, &tip, r.max_tip + 1 + rng.next() % SOL));
        }
        12 => {
            ixs.retain(|ix| ix.program != k(crate::budget::COMPUTE_BUDGET));
            // Limite × prix au-delà de tout plafond (trades et retraits).
            let price = 1_000_000_000_000 + rng.next() % 1_000_000;
            ixs.insert(0, set_compute_unit_limit(250_000)?);
            ixs.insert(1, set_compute_unit_price(price)?);
        }
        13 if is_trade => {
            let d = &mut ixs[ti?].data;
            let mut disc = [0u8; 8];
            disc.copy_from_slice(&rng.next().to_le_bytes());
            d[..8].copy_from_slice(&disc);
        }
        14 if !is_trade => {
            let t = &mut ixs[ti?];
            if rng.below(2) == 0 {
                t.accounts[1].pubkey = THIEF;
            } else {
                let amount = SOL + 1 + rng.next() % SOL;
                t.data[4..12].copy_from_slice(&amount.to_le_bytes());
            }
        }
        _ => return None,
    }
    Some(())
}

#[test]
fn des_milliers_de_transactions_piegees_toutes_refusees() {
    let r = rules();
    let bases = bases(&r);
    assert!(bases.len() >= 10, "pas assez de transactions de base");
    // Témoin : chaque base, intacte, est acceptée (sinon le test ne prouverait rien).
    for b in &bases {
        assert!(
            accepted(&r, b, &W, &b.ixs),
            "base {:?} refusée alors qu'elle est valide",
            b.kind
        );
    }
    let mut rng = Rng(0x5c0e_5160_0003_0000);
    let mut hits = vec![0usize; TRAPS.len()];
    let mut done = 0;
    while done < RUNS {
        // Un retrait une fois sur quatre (une seule base de retrait contre de nombreux trades).
        let b = if rng.below(4) == 0 {
            &bases[bases.len() - 1]
        } else {
            &bases[rng.below(bases.len() - 1)]
        };
        let (mut ixs, mut payer) = (b.ixs.clone(), W);
        let mut applied = Vec::new();
        for _ in 0..=rng.below(3) {
            let t = rng.below(TRAPS.len());
            if trap(t, b, &mut ixs, &mut payer, &mut rng, &r).is_some() {
                applied.push(t);
            }
        }
        if applied.is_empty() {
            continue;
        }
        let names: Vec<&str> = applied.iter().map(|&t| TRAPS[t]).collect();
        assert!(
            !accepted(&r, b, &payer, &ixs),
            "PIÈGE ACCEPTÉ ({:?}) : {names:?}",
            b.kind
        );
        for t in applied {
            hits[t] += 1;
        }
        done += 1;
    }
    // Chaque piège a vraiment été essayé, et souvent.
    for (t, n) in hits.iter().enumerate() {
        assert!(*n >= 100, "piège « {} » trop peu testé ({n})", TRAPS[t]);
    }
}

/// Octets arbitraires (transactions malformées, tronquées, bits inversés) : jamais de panique.
#[test]
fn transactions_malformees_sans_panique() {
    let r = rules();
    let bases = bases(&r);
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for i in 0..50_000 {
        let b = &bases[i % bases.len()];
        let mut raw = compile_legacy(&W, &b.ixs, &[9; 32]).unwrap_or_default();
        for _ in 0..=rng.below(4) {
            let pos = rng.below(raw.len());
            raw[pos] ^= (rng.next() >> 8) as u8 | 1;
        }
        if rng.below(4) == 0 {
            raw.truncate(rng.below(raw.len()));
        }
        if let Ok(msg) = parse_message(&raw) {
            let _ = r.check_trade(&W, &msg, b.expected);
            let _ = check_withdraw(&W, &[0xbb; 32], SOL, &msg);
        }
    }
}
