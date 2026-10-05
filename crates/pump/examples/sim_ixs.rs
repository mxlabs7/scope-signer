//! Outil de DEV / canari : instructions produites par le constructeur Rust pour un coin capturé
//! (courbe pump.fun ou pool PumpSwap), en JSON, pour les faire simuler par mainnet.
//!
//! Usage : cargo run -q -p scope-pump --example sim_ixs -- <fixture.json> <wallet> <sol_lamports>
//! Une seule transaction : achat exact → vente de la moitié estimée (+ WSOL ouvert/refermé sur PumpSwap).

use base64::Engine as _;
use scope_pump::amm::{GlobalConfig, Pool, Swap};
use scope_pump::cu::Existing;
use scope_pump::{BondingCurve, Global, Instruction, Trade};
use scope_solana::{bs58_encode, pubkey};
use serde_json::{Value, json};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, path, user, sol] = args.as_slice() else {
        eprintln!("usage : sim_ixs <fixture.json> <wallet> <sol_lamports>");
        std::process::exit(2);
    };
    let fx: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_default())
        .unwrap_or(Value::Null);
    let sol: u64 = sol.parse().unwrap_or(0);
    let user = pubkey(user).unwrap_or([0; 32]);
    // Instructions + limite de calcul que Scope réserverait (achat + vente, rien n'existant encore).
    let (ixs, cu_limit) = if fx.get("pool").is_some() {
        amm(&fx, user, sol)
    } else {
        curve(&fx, user, sol)
    }
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let out: Vec<Value> = ixs
        .iter()
        .map(|i| {
            json!({
                "program": bs58_encode(&i.program),
                "accounts": i.accounts.iter().map(|a| json!({
                    "pubkey": bs58_encode(&a.pubkey), "signer": a.signer, "writable": a.writable
                })).collect::<Vec<_>>(),
                "data": i.data.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            })
        })
        .collect();
    println!(
        "{}",
        json!({ "mint": fx["mint"], "cu_limit": cu_limit, "instructions": out })
    );
}

fn b64(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap_or_default())
        .unwrap_or_default()
}

fn key(v: &Value) -> [u8; 32] {
    pubkey(v.as_str().unwrap_or_default()).unwrap_or([0; 32])
}

fn num(v: &Value) -> u64 {
    v.as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0)
}

/// Pool PumpSwap : WSOL ouvert → achat exact → vente de la moitié estimée → WSOL refermé.
fn amm(fx: &Value, user: [u8; 32], sol: u64) -> Result<(Vec<Instruction>, u32), String> {
    let config = GlobalConfig::decode(&b64(&fx["accounts"]["global_config"]["data"]))
        .map_err(|e| format!("{e:?}"))?;
    let pool = Pool::decode(&b64(&fx["accounts"]["pool"]["data"])).map_err(|e| format!("{e:?}"))?;
    let swap = Swap {
        config: &config,
        pool: &pool,
        pool_key: key(&fx["pool"]),
        base_token_program: key(&fx["base_token_program"]),
        user,
        fee_recipient_index: 0,
        buyback_index: 0,
    };
    let half = pool.estimate_base_out(
        sol,
        num(&fx["reserves"]["base"]),
        num(&fx["reserves"]["quote"]),
    ) / 2;
    let e = |e: scope_pump::PumpError| format!("{e:?}");
    let mut ixs = swap.open_wsol(sol).map_err(e)?;
    ixs.push(swap.create_base_ata().map_err(e)?);
    ixs.push(swap.buy_exact_quote_in(sol, 1).map_err(e)?);
    ixs.push(swap.sell(half, 1).map_err(e)?);
    ixs.push(swap.close_wsol().map_err(e)?);
    let none = Existing::default();
    let cu = swap.buy_compute_units(&none).map_err(e)?
        + swap.sell_compute_units(&none, false).map_err(e)?;
    Ok((ixs, cu))
}

/// Courbe pump.fun : compte de tokens → achat exact → vente de la moitié estimée.
fn curve(fx: &Value, user: [u8; 32], sol: u64) -> Result<(Vec<Instruction>, u32), String> {
    let global =
        Global::decode(&b64(&fx["accounts"]["global"]["data"])).map_err(|e| format!("{e:?}"))?;
    let curve = BondingCurve::decode(&b64(&fx["accounts"]["bonding_curve"]["data"]))
        .map_err(|e| format!("{e:?}"))?;
    let trade = Trade {
        global: &global,
        curve: &curve,
        mint: key(&fx["mint"]),
        token_program: key(&fx["token_program"]),
        user,
        fee_recipient_index: 0,
        buyback_index: 0,
    };
    let e = |e: scope_pump::PumpError| format!("{e:?}");
    let cu = trade.buy_compute_units(&Existing::default()).map_err(e)?
        + trade.sell_compute_units(false).map_err(e)?;
    Ok((
        vec![
            trade.create_user_ata().map_err(e)?,
            trade.buy_exact_sol_in(sol, 1).map_err(e)?,
            trade
                .sell(curve.estimate_tokens_out(sol) / 2, 1)
                .map_err(e)?,
        ],
        cu,
    ))
}
