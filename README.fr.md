# Scope — signer et règles de fees (code public)

[Scope](https://scopebot.trade) est un outil de sniping et de copy trading Solana pour pump.fun.
Ce dépôt contient la partie qui **garde et utilise tes clés** : le signer. Tout ce qui touche à tes fonds est
ici, pour que chacun puisse vérifier ce qu'il peut faire et ce qu'il ne peut pas faire.

## Contenu

| Dossier | Rôle |
|---|---|
| `crates/signer` | Le **signer** : un processus isolé qui garde les clés des wallets (chiffrées) et signe les transactions. **Aucun accès au réseau.** |
| `crates/solana` | Lecture des messages Solana : le signer lit chaque transaction avant de la signer. |
| `crates/pump` | Format des instructions pump.fun / PumpSwap (utilisé par les tests du signer). |
| `crates/protocol` | Messages échangés avec le signer (socket local, trames binaires). |
| `crates/keytool` | Outil de clé maître : génération hors ligne, sauvegarde Shamir 2 sur 3, récupération, signature des règles. |
| `infra/rules/rules.json` | Les **règles** appliquées par le signer : programmes et instructions autorisés, wallet de fees, taux de fee, comptes de tip, plafonds. |

Le moteur, l'API, le bot et la web app ne sont pas ici. Ils peuvent demander une signature, mais le signer
vérifie chaque transaction avec les règles ci-dessous et refuse tout le reste.

## Ce que le signer garantit

1. **Pas de réseau.** Le signer n'a aucun accès au réseau ; il ne parle au moteur que par un socket local.
2. **Seulement des trades pump.fun.** Une transaction de trade ne peut contenir que les instructions de
   `rules.json` (achat/vente sur la courbe pump.fun et sur PumpSwap, fermeture des comptes de volume pump.fun).
3. **Tes tokens et ton SOL restent à toi.** Les comptes de tokens doivent être **les comptes associés de ton
   propre wallet** : un moteur compromis ne peut pas faire livrer les tokens ou le SOL d'une vente ailleurs.
4. **Fee exacte, rien de caché.** Le SOL ne peut aller qu'au wallet de fees (exactement `fee_bps` = 1 % du
   trade), aux comptes de tip Jito (plafonnés) et à ton propre compte de SOL « wrappé ». Tout autre transfert est refusé.
5. **Frais réseau plafonnés.** Priorité et tip sont chacun plafonnés.
6. **Les retraits passent par toi.** Un retrait n'est signé qu'avec une preuve fraîche de ta part (passkey sur
   le web, code d'appli sur Telegram), liée à cette destination et à ce montant précis.
7. **Les clés ne sortent jamais.** La clé privée d'un nouveau wallet t'est montrée **une fois** (scellée
   jusqu'à ta session), puis plus jamais. Les clés sont chiffrées avec une clé maître gardée hors ligne, découpée 2 sur 3.
8. **Règles signées.** `rules.json` n'est appliqué que s'il porte une signature valide de la clé d'autorité
   (gardée hors ligne, jamais sur le serveur). Un fichier de règles modifié sur le serveur est ignoré.

## Vérifier soi-même

```sh
cargo test --workspace
```

`crates/signer/src/attack_tests.rs` envoie au signer **5 000 transactions piégées** (15 types de pièges) et
**50 000 messages malformés**. Toutes doivent être refusées, sans plantage. Affaiblir une règle fait échouer ces tests.

## Licence

Tous droits réservés. Ce code est publié pour que chacun puisse le vérifier ; il n'est pas sous licence de réutilisation.
