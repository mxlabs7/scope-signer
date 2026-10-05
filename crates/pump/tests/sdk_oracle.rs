//! Oracle : sur de VRAIS coins pump.fun capturés depuis mainnet, le constructeur Rust doit produire
//! exactement les instructions du SDK officiel (`tools/pump-oracle/src/capture.ts`).
//! Le SDK achète avec `buy` ; Scope utilise `buy_exact_sol_in` (mêmes comptes, données différentes,
//! accepté par mainnet en simulation) : on compare donc les COMPTES de l'achat, et TOUT pour la vente.

use base64::Engine as _;
use scope_pump::{BondingCurve, Global, Instruction, Trade};
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

/// Instruction pump.fun attendue (la dernière de la liste du SDK, après l'éventuelle création d'ATA).
fn expected(fx: &Value, which: &str) -> Value {
    fx["expected"][which]
        .as_array()
        .and_then(|a| a.last())
        .cloned()
        .unwrap_or_else(|| panic!("{which} absent"))
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

#[test]
fn identique_au_sdk_officiel_sur_de_vrais_coins() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{e}")) {
        let path = entry.unwrap_or_else(|e| panic!("{e}")).path();
        if path.extension().is_none_or(|x| x != "json") {
            continue; // sous-dossier amm/ : test dédié
        }
        let fx: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_default())
            .unwrap_or(Value::Null);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let global = Global::decode(&b64(&fx["accounts"]["global"]["data"]))
            .unwrap_or_else(|e| panic!("{name} global {e:?}"));
        let curve = BondingCurve::decode(&b64(&fx["accounts"]["bonding_curve"]["data"]))
            .unwrap_or_else(|e| panic!("{name} courbe {e:?}"));
        assert_eq!(
            curve.is_mayhem_mode,
            fx["flags"]["mayhem"].as_bool().unwrap_or(false),
            "{name}"
        );
        assert_eq!(
            curve.is_cashback_coin,
            fx["flags"]["cashback"].as_bool().unwrap_or(false),
            "{name}"
        );

        let sdk_buy = expected(&fx, "buy");
        let sdk_sell = expected(&fx, "sell");
        // Le SDK tire au hasard le destinataire des fees et du buyback : on reprend son choix.
        let pick = |ix: &Value, fee_pos: usize, buyback_from_end: usize, list: &[Pubkey]| {
            let acc = ix["accounts"].as_array().cloned().unwrap_or_default();
            let fee = key(&acc[fee_pos]["pubkey"]);
            let buyback = key(&acc[acc.len() - buyback_from_end]["pubkey"]);
            let fi = list
                .iter()
                .position(|k| *k == fee)
                .unwrap_or_else(|| panic!("{name} : fee recipient inconnu"));
            let bi = global
                .buyback_fee_recipients
                .iter()
                .position(|k| *k == buyback)
                .unwrap_or_else(|| panic!("{name} : buyback inconnu"));
            (fi, bi)
        };
        let fee_list = global.fee_recipients_for(curve.is_mayhem_mode);

        let (fi, bi) = pick(&sdk_buy, 1, 1, &fee_list);
        let trade = Trade {
            global: &global,
            curve: &curve,
            mint: key(&fx["mint"]),
            token_program: key(&fx["token_program"]),
            user: key(&fx["user"]),
            fee_recipient_index: fi,
            buyback_index: bi,
        };
        let buy = trade
            .buy_exact_sol_in(10_000_000, 1)
            .unwrap_or_else(|e| panic!("{name} achat {e:?}"));
        assert_eq!(
            accounts(&buy),
            sdk_accounts(&sdk_buy),
            "{name} : comptes de l'achat"
        );
        assert_eq!(buy.program, key(&sdk_buy["program"]));

        let (fi, bi) = pick(&sdk_sell, 1, 1, &fee_list);
        let trade = Trade {
            fee_recipient_index: fi,
            buyback_index: bi,
            ..trade
        };
        // Mêmes montants que le SDK : relus dans ses données (tokens, minimum de SOL).
        let data = unhex(sdk_sell["data"].as_str().unwrap_or_default());
        let amount = u64::from_le_bytes(data[8..16].try_into().unwrap_or_default());
        let min_out = u64::from_le_bytes(data[16..24].try_into().unwrap_or_default());
        let sell = trade
            .sell(amount, min_out)
            .unwrap_or_else(|e| panic!("{name} vente {e:?}"));
        assert_eq!(
            accounts(&sell),
            sdk_accounts(&sdk_sell),
            "{name} : comptes de la vente"
        );
        assert_eq!(sell.data, data, "{name} : données de la vente");

        // Création du compte de tokens : identique à la première instruction du SDK.
        let sdk_ata = &fx["expected"]["buy"][0];
        let ata = trade.create_user_ata().unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            accounts(&ata),
            sdk_accounts(sdk_ata),
            "{name} : création d'ATA"
        );
        assert_eq!(
            ata.data,
            unhex(sdk_ata["data"].as_str().unwrap_or_default())
        );
        // Estimations : jamais au-dessus du SDK (prudentes), et à moins de 2 % de lui.
        let inputs = &fx["inputs"];
        let num = |k: &str| {
            inputs[k]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        };
        let tokens = curve.estimate_tokens_out(num("sol_in"));
        assert!(
            tokens <= num("tokens_out"),
            "{name} : estimation d'achat trop optimiste"
        );
        assert!(
            tokens as f64 >= num("tokens_out") as f64 * 0.98,
            "{name} : estimation d'achat trop pessimiste"
        );
        let sol = curve.estimate_sol_out(num("sell_tokens"));
        assert!(
            sol <= num("sol_out"),
            "{name} : estimation de vente trop optimiste ({sol} > {})",
            num("sol_out")
        );
        assert!(
            sol as f64 >= num("sol_out") as f64 * 0.98,
            "{name} : estimation de vente trop pessimiste"
        );
        checked += 1;
    }
    assert!(checked >= 2, "pas assez de coins capturés ({checked})");
}
