//! Décodeur des événements pump.fun, sur de VRAIS messages de création reçus par WebSocket
//! (`tools/pump-oracle/src/capture-launches.ts`).

use scope_pump::events::{Event, decode_logs};
use scope_solana::bs58_encode;
use serde_json::Value;

#[test]
fn decode_les_vraies_creations() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/events");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{e}")) {
        let path = entry.unwrap_or_else(|e| panic!("{e}")).path();
        let fx: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_default())
            .unwrap_or(Value::Null);
        let logs: Vec<String> = fx["logs"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|l| l.as_str().map(String::from))
            .collect();
        let events = decode_logs(&logs);
        let created: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let Event::Create(c) = e {
                    Some(c)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(created.len(), 1, "{path:?} : une création attendue");
        let c = created[0];
        // Cohérence : mint pump.fun, réserves initiales standard, créateur et symbole présents.
        assert!(!c.symbol.is_empty() && !c.name.is_empty(), "{path:?}");
        assert_eq!(
            c.token_total_supply, 1_000_000_000_000_000,
            "{path:?} : offre totale pump.fun"
        );
        assert!(c.virtual_sol_reserves > 0 && c.virtual_token_reserves > c.real_token_reserves);
        assert_ne!(c.creator, [0; 32]);
        assert!(
            bs58_encode(&c.token_program).starts_with("Token"),
            "{path:?} : programme de token"
        );
        // Achat du créateur au lancement : même coin.
        for e in &events {
            if let Event::Trade(t) = e {
                assert_eq!(t.mint, c.mint);
                assert!(t.is_buy);
                // Fin d'événement décodée : instruction d'origine et cotation identique à la création.
                assert!(t.ix_name.starts_with("buy"), "{path:?} : {}", t.ix_name);
                assert_eq!(t.quote_mint, c.quote_mint, "{path:?}");
            }
        }
        // État de la courbe sans appel réseau : après l'achat du créateur s'il y en a un.
        let curve =
            scope_pump::BondingCurve::from_events(&events).unwrap_or_else(|| panic!("{path:?}"));
        assert_eq!(curve.creator, c.creator);
        let dev_bought = events.iter().any(|e| matches!(e, Event::Trade(_)));
        assert_eq!(curve.real_quote_reserves > 0, dev_bought, "{path:?}");
        assert!(curve.estimate_tokens_out(10_000_000) > 0);
        checked += 1;
    }
    assert!(checked >= 3);
}

#[test]
fn ignore_les_donnees_illisibles_sans_paniquer() {
    for line in [
        "Program data: ",
        "Program data: !!!",
        "Program data: AAAA",
        "Program log: x",
        "Program data: G3KpTd7rY3b/////////",
    ] {
        assert!(decode_logs(&[line]).is_empty());
    }
}

/// Copy : le drapeau cashback se déduit de l'achat seul (part cashback non nulle), comme à la création.
#[test]
fn cashback_deduit_d_un_achat_identique_a_la_creation() {
    let raw = include_str!("fixtures/launches/sample.jsonl");
    let (mut checked, mut cashback) = (0, 0);
    for line in raw.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture");
        let logs: Vec<String> = serde_json::from_value(v["logs"].clone()).expect("fixture");
        let events = decode_logs(&logs);
        let Some(c) = events.iter().find_map(|e| match e {
            Event::Create(c) => Some(c),
            _ => None,
        }) else {
            continue;
        };
        for e in &events {
            if let Event::Trade(t) = e
                && t.mint == c.mint
            {
                let from_trade = scope_pump::BondingCurve::from_trade(t);
                assert_eq!(
                    from_trade.is_cashback_coin, c.is_cashback_enabled,
                    "{}",
                    v["signature"]
                );
                checked += 1;
                cashback += usize::from(c.is_cashback_enabled);
            }
        }
    }
    println!("{checked} achats vérifiés dont {cashback} sur coins cashback");
    assert!(checked >= 5);
}
