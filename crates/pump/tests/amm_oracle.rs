//! Oracle PumpSwap : sur de VRAIS pools capturés depuis mainnet (`tools/pump-oracle/src/capture-amm.ts`),
//! le constructeur Rust doit produire exactement les instructions du SDK officiel.
//! Le SDK achète avec `buy` ; Scope utilise `buy_exact_quote_in` (mêmes comptes, données différentes,
//! validé par simulation mainnet) : on compare les COMPTES de l'achat, et TOUT pour la vente.

use base64::Engine as _;
use scope_pump::Instruction;
use scope_pump::amm::{GlobalConfig, Pool, Swap, canonical_pool};
use scope_solana::{Pubkey, pubkey};
use serde_json::Value;

fn key(v: &Value) -> Pubkey {
    pubkey(v.as_str().unwrap_or_default()).unwrap_or_else(|| panic!("adresse invalide : {v}"))
}

fn b64(v: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(v.as_str().unwrap_or_default())
        .unwrap_or_default()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect()
}

fn accounts(ix: &Instruction) -> Vec<(Pubkey, bool, bool)> {
    ix.accounts
        .iter()
        .map(|a| (a.pubkey, a.signer, a.writable))
        .collect()
}

fn sdk_accounts(v: &Value) -> Vec<(Pubkey, bool, bool)> {
    v["accounts"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .map(|a| {
            (
                key(&a["pubkey"]),
                a["signer"].as_bool().unwrap_or(false),
                a["writable"].as_bool().unwrap_or(false),
            )
        })
        .collect()
}

fn num(v: &Value) -> u64 {
    v.as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
}

#[test]
fn identique_au_sdk_officiel_sur_de_vrais_pools() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/amm");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{e}")) {
        let path = entry.unwrap_or_else(|e| panic!("{e}")).path();
        let fx: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_default())
            .unwrap_or(Value::Null);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let config = GlobalConfig::decode(&b64(&fx["accounts"]["global_config"]["data"]))
            .unwrap_or_else(|e| panic!("{name} config {e:?}"));
        let pool = Pool::decode(&b64(&fx["accounts"]["pool"]["data"]))
            .unwrap_or_else(|e| panic!("{name} pool {e:?}"));
        let mint = key(&fx["mint"]);
        assert_eq!(pool.base_mint, mint, "{name}");
        assert_eq!(
            canonical_pool(&mint),
            Ok(key(&fx["pool"])),
            "{name} : pool canonique"
        );
        assert_eq!(
            pool.is_mayhem_mode,
            fx["flags"]["mayhem"].as_bool().unwrap_or(false)
        );
        assert_eq!(
            pool.is_cashback_coin,
            fx["flags"]["cashback"].as_bool().unwrap_or(false)
        );

        let sdk_buy = &fx["expected"]["buy"][0];
        let sdk_sell = &fx["expected"]["sell"][0];
        // Le SDK tire au hasard le destinataire des fees (compte 9) et du buyback (avant-dernier).
        let pick = |ix: &Value| {
            let acc = ix["accounts"].as_array().cloned().unwrap_or_default();
            let fee = key(&acc[9]["pubkey"]);
            let buyback = key(&acc[acc.len() - 2]["pubkey"]);
            let fi = config
                .fee_recipients_for(pool.is_mayhem_mode)
                .iter()
                .position(|k| *k == fee)
                .unwrap_or_else(|| panic!("{name} : fee recipient inconnu"));
            let bi = config
                .buyback_fee_recipients
                .iter()
                .position(|k| *k == buyback)
                .unwrap_or_else(|| panic!("{name} : buyback inconnu"));
            (fi, bi)
        };

        let (fi, bi) = pick(sdk_buy);
        let swap = Swap {
            config: &config,
            pool: &pool,
            pool_key: key(&fx["pool"]),
            base_token_program: key(&fx["base_token_program"]),
            user: key(&fx["user"]),
            fee_recipient_index: fi,
            buyback_index: bi,
        };
        let buy = swap
            .buy_exact_quote_in(10_000_000, 1)
            .unwrap_or_else(|e| panic!("{name} achat {e:?}"));
        assert_eq!(
            accounts(&buy),
            sdk_accounts(sdk_buy),
            "{name} : comptes de l'achat"
        );
        assert_eq!(buy.program, key(&sdk_buy["program"]));
        // Données : discriminateur buy_exact_quote_in, SOL exact, minimum, track_volume.
        let mut data = vec![0xc6, 0x2e, 0x15, 0x52, 0xb4, 0xd9, 0xe8, 0x70];
        data.extend_from_slice(&10_000_000u64.to_le_bytes());
        data.extend_from_slice(&1u64.to_le_bytes());
        data.push(1);
        assert_eq!(buy.data, data);

        let (fi, bi) = pick(sdk_sell);
        let swap = Swap {
            fee_recipient_index: fi,
            buyback_index: bi,
            ..swap
        };
        let data = unhex(sdk_sell["data"].as_str().unwrap_or_default());
        let base_in = u64::from_le_bytes(data[8..16].try_into().unwrap_or_default());
        let min_out = u64::from_le_bytes(data[16..24].try_into().unwrap_or_default());
        let sell = swap
            .sell(base_in, min_out)
            .unwrap_or_else(|e| panic!("{name} vente {e:?}"));
        assert_eq!(
            accounts(&sell),
            sdk_accounts(sdk_sell),
            "{name} : comptes de la vente"
        );
        assert_eq!(sell.data, data, "{name} : données de la vente");

        // Fermeture du compte WSOL : identique à la dernière instruction du SDK (vente).
        let sdk_close = fx["expected"]["sell_all"]
            .as_array()
            .and_then(|a| a.last())
            .cloned()
            .unwrap_or_default();
        let close = swap.close_wsol().unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            accounts(&close),
            sdk_accounts(&sdk_close),
            "{name} : fermeture WSOL"
        );
        assert_eq!(
            close.data,
            unhex(sdk_close["data"].as_str().unwrap_or_default())
        );

        // Estimations : jamais au-dessus du SDK (prudentes), et à moins de 2 % de lui.
        let (rb, rq) = (num(&fx["reserves"]["base"]), num(&fx["reserves"]["quote"]));
        let inputs = &fx["inputs"];
        let base = pool.estimate_base_out(num(&inputs["sol_in"]), rb, rq);
        let sdk_base = num(&inputs["base_out"]);
        assert!(
            base <= sdk_base,
            "{name} : achat trop optimiste ({base} > {sdk_base})"
        );
        assert!(
            base as f64 >= sdk_base as f64 * 0.98,
            "{name} : achat trop pessimiste ({base} / {sdk_base})"
        );
        let sol = pool.estimate_sol_out(num(&inputs["sell_base"]), rb, rq);
        let sdk_sol = num(&inputs["quote_out"]);
        assert!(
            sol <= sdk_sol,
            "{name} : vente trop optimiste ({sol} > {sdk_sol})"
        );
        assert!(
            sol as f64 >= sdk_sol as f64 * 0.98,
            "{name} : vente trop pessimiste ({sol} / {sdk_sol})"
        );
        checked += 1;
    }
    assert!(checked >= 2, "pas assez de pools capturés ({checked})");
}
