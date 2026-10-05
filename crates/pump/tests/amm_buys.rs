//! Achats PumpSwap réels (tests/fixtures/amm-buys) : l'événement se décode, et le pool reconstruit
//! sans appel réseau est identique au compte on-chain sur tout ce que l'achat utilise.

use base64::Engine as _;
use scope_pump::amm::Pool;
use scope_pump::events::{Event, decode_logs};
use scope_solana::pubkey;

#[test]
fn pool_reconstruit_depuis_un_achat_identique_au_compte_reel() {
    let raw = include_str!("fixtures/amm-buys/sample.jsonl");
    let mut checked = 0;
    for line in raw.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture");
        let logs: Vec<String> = serde_json::from_value(v["logs"].clone()).expect("fixture");
        let mint = pubkey(v["mint"].as_str().expect("fixture")).expect("fixture");
        let owner = pubkey(v["mint_owner"].as_str().expect("fixture")).expect("fixture");
        let data = base64::engine::general_purpose::STANDARD
            .decode(v["pool_data"].as_str().expect("fixture"))
            .expect("fixture");
        let real = Pool::decode(&data).expect("fixture");
        let ev = decode_logs(&logs)
            .into_iter()
            .find_map(|e| match e {
                Event::AmmBuy(b)
                    if b.pool == pubkey(v["pool"].as_str().expect("fixture")).expect("fixture") =>
                {
                    Some(b)
                }
                _ => None,
            })
            .expect("achat PumpSwap décodé");
        assert!(ev.ix_name.starts_with("buy"), "{}", ev.ix_name);
        let sig = v["signature"].as_str().expect("fixture");
        match Pool::from_buy(&mint, &owner, &ev).expect("fixture") {
            None => assert_ne!(
                real.quote_mint,
                pubkey(scope_solana::WSOL_MINT).unwrap_or_default(),
                "{sig} : pool coté en SOL non reconnu canonique"
            ),
            Some((_, p)) => {
                assert_eq!(p.base_mint, real.base_mint, "{sig}");
                assert_eq!(
                    p.pool_base_token_account, real.pool_base_token_account,
                    "{sig}"
                );
                assert_eq!(
                    p.pool_quote_token_account, real.pool_quote_token_account,
                    "{sig}"
                );
                assert_eq!(p.coin_creator, real.coin_creator, "{sig}");
                assert_eq!(p.is_cashback_coin, real.is_cashback_coin, "{sig}");
                assert_eq!(
                    p.virtual_quote_reserves, real.virtual_quote_reserves,
                    "{sig}"
                );
                assert_eq!(p.creator, real.creator, "{sig}");
                println!(
                    "{sig} ok (len réel {}, creator_fee_bps {})",
                    real.len, real.creator_fee_bps
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 5,
        "seulement {checked} pools canoniques vérifiés"
    );
}

/// Ventes PumpSwap réelles : décodées, vendeur = signataire, réserves cohérentes.
#[test]
fn ventes_pumpswap_decodees() {
    let raw = include_str!("fixtures/amm-buys/sells.jsonl");
    let mut n = 0;
    for line in raw.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture");
        let logs: Vec<String> = serde_json::from_value(v["logs"].clone()).expect("fixture");
        let signer = pubkey(v["signer"].as_str().expect("fixture")).expect("fixture");
        let sells: Vec<_> = decode_logs(&logs)
            .into_iter()
            .filter_map(|e| match e {
                Event::AmmSell(s) => Some(s),
                _ => None,
            })
            .collect();
        assert!(!sells.is_empty(), "{}", v["signature"]);
        for s in sells {
            assert!(s.base_amount_in > 0 && s.pool_base_token_reserves > 0);
            assert!(s.quote_amount_out_without_lp_fee < s.pool_quote_token_reserves);
            let (base, quote) = s.reserves_after();
            assert_eq!(base, s.pool_base_token_reserves + s.base_amount_in);
            assert_eq!(
                quote,
                s.pool_quote_token_reserves - s.quote_amount_out_without_lp_fee
            );
            if s.user == signer {
                n += 1;
            }
        }
    }
    assert!(
        n >= 3,
        "seulement {n} ventes dont le vendeur est le signataire"
    );
}
