# Scope — signer & fee rules (public code)

[Scope](https://scopebot.trade) is a Solana sniper and copy-trading tool for pump.fun.
This repository contains the part that **holds and uses your keys**: the signer. Everything that touches
your funds is here, so anyone can check what it can and cannot do.

> 🇫🇷 Version française : [README.fr.md](README.fr.md)

## What is in this repository

| Folder | Role |
|---|---|
| `crates/signer` | The **signer**: an isolated process that stores wallet keys (encrypted) and signs transactions. It runs with **no network access**. |
| `crates/solana` | Minimal Solana message parsing used by the signer to read every transaction before signing it. |
| `crates/pump` | pump.fun / PumpSwap instruction layouts (used by the signer's tests). |
| `crates/protocol` | Messages exchanged with the signer (a Unix socket, binary frames). |
| `crates/keytool` | Master-key tooling: offline generation, 2-of-3 Shamir backup and recovery, rules signing. |
| `infra/rules/rules.json` | The **rules** the signer enforces: allowed programs and instructions, the fee wallet, the fee rate, tip accounts, fee caps. |

The trading engine, the API, the bot and the web app are not in this repository. They can ask the signer to
sign, but the signer checks every transaction against the rules below and refuses anything else.

## What the signer guarantees

1. **No network.** The signer has no network access; it only talks to the engine through a local socket.
2. **Only pump.fun trades.** A trade transaction may only contain the instructions listed in `rules.json`
   (pump.fun curve buy/sell, PumpSwap buy/sell, and closing pump.fun volume accounts). Anything else is refused.
3. **Your tokens and SOL stay yours.** For each instruction, the token accounts must be the **associated
   accounts of your own wallet**. A compromised engine cannot route bought tokens or sale proceeds elsewhere.
4. **Exact fee, nothing hidden.** SOL may only go to: the fee wallet (exactly `fee_bps` = 1% of the trade),
   the Jito tip accounts (capped), and your own wrapped-SOL account. Any other transfer is refused.
5. **Capped network fees.** Priority fee and tip are each capped (`max_priority_lamports`, `max_tip_lamports`).
6. **Withdrawals need you.** A withdrawal is signed only with a fresh proof from you (a passkey on the web,
   an app code on Telegram), bound to that exact destination and amount.
7. **Keys are never exported.** A new wallet's private key is shown to you **once** (sealed end-to-end to your
   session), then never again. Keys are stored encrypted with a master key kept offline, split 2-of-3.
8. **Signed rules.** `rules.json` is only applied if it carries a valid signature from the rules authority
   key (kept offline, never on the server). A modified rules file on the server is ignored.

## Check it yourself

```sh
cargo test --workspace            # all tests, including the attack tests below
```

`crates/signer/src/attack_tests.rs` throws **5,000 crafted transactions** (15 kinds of traps: extra transfers,
wrong token accounts, unknown programs, inflated fees, duplicated compute budgets…) and **50,000 malformed
messages** at the signer. Every one must be refused, without a crash. If you weaken a rule, these tests fail.

## The fee

The fee is **1% of each buy and each sell**, paid inside the same transaction to the fee wallet listed in
`infra/rules/rules.json`. It is checked by the signer at signing time, so it cannot be changed silently.

## License

All rights reserved. This code is published so anyone can audit it; it is not licensed for reuse.
