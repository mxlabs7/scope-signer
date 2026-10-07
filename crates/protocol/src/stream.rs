//! Messages JSON échangés via Redis Streams.
//! Règle : tout montant voyage en chaîne de caractères (u64 → JS perd la précision au-delà de 2^53).

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Version du protocole, écrite dans chaque entrée de stream (champ `v`).
pub const PROTOCOL_VERSION: &str = "1";
/// Commandes vers le moteur (écrites par l'API).
pub const CMD_STREAM: &str = "scope:cmd";
/// Événements émis par le moteur (lus par l'API et le bot).
pub const EVT_STREAM: &str = "scope:evt";
/// Champ qui contient le message JSON dans chaque entrée de stream.
pub const MSG_FIELD: &str = "msg";
/// Champ qui contient la version du protocole.
pub const VERSION_FIELD: &str = "v";

/// Retraits : budget de calcul fixe (un transfert consomme ~150 unités) et prix de priorité modeste.
pub const WITHDRAW_CU_LIMIT: u32 = 1_000;
pub const WITHDRAW_CU_PRICE_MICRO_LAMPORTS: u64 = 1_000_000;
/// Frais réseau EXACTS d'un retrait : 5 000 (signature) + 1 000 × 1 000 000 / 10⁶ (priorité).
pub const WITHDRAW_NETWORK_FEE: u64 = 6_000;

/// À qui renvoyer le résultat.
#[derive(Serialize, Deserialize, TS, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "channel", rename_all = "snake_case")]
#[ts(export)]
pub enum ReplyTo {
    Telegram {
        chat_id: String,
    },
    Web {
        session: String,
    },
    /// Réponse attendue par l'API elle-même (requête/réponse, identifiée par l'`id` de la commande).
    Api,
    /// Notification spontanée du moteur (achat/vente auto) : à l'utilisateur, sur Telegram ET sur le web.
    User {
        user_id: String,
    },
}

/// Commande envoyée au moteur.
#[derive(Serialize, Deserialize, TS, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export)]
pub enum Command {
    /// Palier 1 : traverse toute la chaîne et fait signer un message de test au signer.
    Ping {
        id: String,
        reply: ReplyTo,
        /// Horodatage de la demande (ms depuis l'epoch), en chaîne.
        requested_at_ms: String,
    },
    /// Crée un wallet. La clé privée revient SCELLÉE pour `seal_to` (clé X25519 éphémère de l'API, hex).
    CreateWallet {
        id: String,
        reply: ReplyTo,
        user_id: String,
        seal_to: String,
    },
    /// Importe un wallet. `sealed` (hex) est scellé pour la clé de transport du signer.
    ImportWallet {
        id: String,
        reply: ReplyTo,
        user_id: String,
        sealed: String,
    },
    /// Demande la clé de transport du signer (pour lui sceller un secret).
    TransportKey { id: String, reply: ReplyTo },
    /// Nonce à usage unique émis par le signer, pour construire le défi d'une action sensible.
    NewNonce {
        id: String,
        reply: ReplyTo,
        user_id: String,
    },
    /// Enregistre une passkey dans le registre du signer.
    /// `credential_id` en base64url, `cose` en hex, `seal_to` (clé X25519 éphémère de l'API) en hex.
    RegisterPasskey {
        id: String,
        reply: ReplyTo,
        user_id: String,
        credential_id: String,
        cose: String,
        seal_to: String,
        proof: ProofJson,
    },
    /// Consomme un code de secours (connexion de secours).
    VerifyRecovery {
        id: String,
        reply: ReplyTo,
        user_id: String,
        code: String,
    },
    /// Achat sur pump.fun d'un montant de SOL EXACT.
    Buy {
        id: String,
        reply: ReplyTo,
        user_id: String,
        /// Wallet (base58) de l'utilisateur.
        wallet: String,
        /// Mint du coin (base58).
        mint: String,
        /// SOL à dépenser, en lamports (chaîne).
        sol_lamports: String,
        params: TradeParams,
    },
    /// Vente sur pump.fun d'une part des tokens détenus.
    Sell {
        id: String,
        reply: ReplyTo,
        user_id: String,
        wallet: String,
        mint: String,
        /// Part à vendre, en points de base (10 000 = tout).
        percent_bps: u16,
        params: TradeParams,
    },
    /// Positions (tokens détenus) des wallets d'un utilisateur, lues on-chain. Lecture seule.
    Positions {
        id: String,
        reply: ReplyTo,
        /// Wallets (base58) de l'utilisateur.
        wallets: Vec<String>,
    },
    /// Soldes de SOL des wallets d'un utilisateur, lus on-chain. Lecture seule.
    Balances {
        id: String,
        reply: ReplyTo,
        wallets: Vec<String>,
    },
    /// Combien la récupération rendrait, par wallet (compteurs pump.fun + cashback). Lecture seule.
    ReclaimQuote {
        id: String,
        reply: ReplyTo,
        wallets: Vec<String>,
    },
    /// Retrait de SOL, validé par une passkey sur le défi `challenge::withdraw` (wallet, destination,
    /// montant). Le signer revérifie tout : la preuve, et que la transaction ne fait que ce transfert.
    Withdraw {
        id: String,
        reply: ReplyTo,
        user_id: String,
        wallet: String,
        /// Adresse de destination (base58).
        to: String,
        /// Montant EXACT transféré, en lamports (chaîne). Les frais réseau s'y ajoutent.
        lamports: String,
        proof: ProofJson,
    },
    /// Un groupe de ruggers a changé (créé, modifié ou supprimé) : le moteur le relit en base.
    /// Pas de réponse attendue ; une notification perdue est rattrapée par la relecture périodique.
    GroupChanged {
        id: String,
        reply: ReplyTo,
        group_id: String,
    },
    /// Récupère les dépôts des compteurs de volume pump.fun d'un wallet (cashback réclamé d'abord ;
    /// refus si des récompenses seraient perdues). Aucune fee Scope.
    Reclaim {
        id: String,
        reply: ReplyTo,
        user_id: String,
        wallet: String,
        /// Fermer aussi les comptes de tokens vides (page Reclaim de la web app). Absent : non.
        #[serde(default)]
        accounts: bool,
    },
    /// Prépare un code d'appli (secret généré par le signer, renvoyé scellé pour `seal_to`).
    TotpSetup {
        id: String,
        reply: ReplyTo,
        user_id: String,
        seal_to: String,
        proof: ProofJson,
    },
    /// Active le code d'appli préparé avec un premier code valide.
    TotpConfirm {
        id: String,
        reply: ReplyTo,
        user_id: String,
        code: String,
        seal_to: String,
    },
    /// Vérifie un code d'appli (connexion web) : le signer seul détient le secret.
    VerifyTotp {
        id: String,
        reply: ReplyTo,
        user_id: String,
        code: String,
    },
    /// Remplace les codes de secours (preuve exigée).
    RegenerateRecovery {
        id: String,
        reply: ReplyTo,
        user_id: String,
        seal_to: String,
        proof: ProofJson,
    },
}

/// Paramètres d'exécution communs à un trade.
#[derive(Serialize, Deserialize, TS, Debug, Clone, PartialEq, Eq)]
#[ts(export)]
pub struct TradeParams {
    /// Tolérance de prix, en points de base (1 000 = 10 %).
    pub slippage_bps: u16,
    /// Prix de priorité (micro-lamports par unité de calcul), en chaîne ; « auto » = tarif réel du moment.
    pub priority_micro_lamports: String,
    /// Tip Jito en lamports (« 0 » = aucun), en chaîne.
    pub tip_lamports: String,
}

/// Preuve d'une action sensible (voir `signer_frame::Proof`). Champs WebAuthn en base64url, tels que
/// renvoyés par le navigateur ; nonce en hex.
#[derive(Serialize, Deserialize, TS, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum ProofJson {
    None,
    Passkey {
        nonce: String,
        credential_id: String,
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
    Recovery {
        code: String,
    },
    /// Code d'appli à 6 chiffres.
    Totp {
        code: String,
    },
}

/// Tokens d'un coin détenus par un wallet (solde lu on-chain).
#[derive(Serialize, Deserialize, TS, Debug, Clone, PartialEq, Eq)]
#[ts(export)]
pub struct Position {
    pub wallet: String,
    pub mint: String,
    /// Solde brut (en plus petites unités), en chaîne.
    pub amount: String,
    pub decimals: u8,
    /// Où il se trade : curve | pumpswap | other (pas un coin pump.fun : non vendable par Scope).
    pub venue: String,
    /// Valeur estimée si tout est vendu maintenant (lamports, frais pump.fun déduits, estimation
    /// prudente). Absente si le coin n'est pas vendable par Scope.
    pub value_lamports: Option<String>,
}

/// Solde de SOL d'un wallet (lu on-chain).
#[derive(Serialize, Deserialize, TS, Debug, Clone, PartialEq, Eq)]
#[ts(export)]
pub struct Balance {
    pub wallet: String,
    /// Lamports, en chaîne.
    pub lamports: String,
}

/// Ce que la récupération rendrait pour un wallet.
#[derive(Serialize, Deserialize, TS, Debug, Clone, PartialEq, Eq)]
#[ts(export)]
pub struct ReclaimQuote {
    pub wallet: String,
    /// Lamports récupérables (dépôts des compteurs + cashback), en chaîne.
    pub lamports: String,
    /// Raison si la récupération est bloquée pour l'instant (récompenses à réclamer sur pump.fun).
    pub blocked: Option<String>,
    /// Comptes de tokens vides fermables, et leur loyer total (lamports, en chaîne).
    pub accounts: u32,
    pub accounts_lamports: String,
}

/// Événement émis par le moteur.
#[derive(Serialize, Deserialize, TS, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export)]
pub enum Event {
    /// Achat ou vente automatique d'un groupe de ruggers.
    AutoTrade {
        id: String,
        reply: ReplyTo,
        /// Nom du groupe.
        group: String,
        /// Déclencheur : « snipe », « copy », « tp », « sl », « dev_sell », « timed ».
        action: String,
        /// « buy » ou « sell ».
        side: String,
        mint: String,
        wallet: String,
        /// « dry_run » (à blanc), « sent », « confirmed » ou « failed ».
        status: String,
        signature: Option<String>,
        /// SOL engagé (achat) ou attendu (vente), en lamports.
        sol_lamports: String,
        /// Fee Scope de la transaction, en lamports.
        fee_lamports: String,
        /// Précision : raison d'un échec, palier de TP…
        detail: Option<String>,
    },
    /// SOL reçu sur un wallet de l'utilisateur (dépôt venant de l'extérieur).
    Deposit {
        id: String,
        reply: ReplyTo,
        wallet: String,
        lamports: String,
        signature: String,
    },
    Pong {
        id: String,
        reply: ReplyTo,
        /// Clé publique du signer (base58).
        signer_pubkey: String,
        /// Signature du message de test (base58), vérifiée par le moteur.
        signature: String,
        /// Temps d'aller-retour moteur → signer → moteur, en microsecondes.
        signer_roundtrip_us: u32,
    },
    WalletCreated {
        id: String,
        reply: ReplyTo,
        /// Adresse du wallet (base58).
        pubkey: String,
        /// Clé privée scellée pour l'API (hex). Jamais en clair dans Redis.
        sealed: String,
    },
    WalletImported {
        id: String,
        reply: ReplyTo,
        pubkey: String,
    },
    TransportKey {
        id: String,
        reply: ReplyTo,
        /// Clé publique X25519 du signer (hex).
        key: String,
    },
    Nonce {
        id: String,
        reply: ReplyTo,
        /// Nonce à usage unique (hex).
        nonce: String,
    },
    PasskeyRegistered {
        id: String,
        reply: ReplyTo,
        /// Codes de secours scellés pour l'API (hex), au tout premier facteur uniquement.
        recovery_sealed: Option<String>,
    },
    RecoveryCodes {
        id: String,
        reply: ReplyTo,
        sealed: String,
    },
    /// Action réussie, sans donnée en retour.
    Done { id: String, reply: ReplyTo },
    /// Résultat d'un trade. `status` : confirmed | failed.
    Trade {
        id: String,
        reply: ReplyTo,
        /// Signature de la transaction (base58), absente si rien n'a été envoyé.
        signature: Option<String>,
        status: String,
        /// Raison de l'échec, le cas échéant.
        error: Option<String>,
        /// SOL engagé (achat) ou attendu (vente), en lamports.
        sol_lamports: String,
        /// Fee Scope prélevée, en lamports.
        fee_lamports: String,
    },
    Positions {
        id: String,
        reply: ReplyTo,
        positions: Vec<Position>,
    },
    Balances {
        id: String,
        reply: ReplyTo,
        balances: Vec<Balance>,
    },
    ReclaimQuotes {
        id: String,
        reply: ReplyTo,
        quotes: Vec<ReclaimQuote>,
    },
    /// Résultat d'une récupération. `status` : confirmed | failed | nothing (aucun compteur).
    Reclaimed {
        id: String,
        reply: ReplyTo,
        signature: Option<String>,
        status: String,
        error: Option<String>,
        /// SOL récupéré (dépôts + cashback), en lamports.
        lamports: String,
    },
    /// Secret du code d'appli, scellé pour l'API (hex).
    TotpSecret {
        id: String,
        reply: ReplyTo,
        sealed: String,
    },
    /// Résultat d'un retrait. `status` : confirmed | failed.
    Withdrawn {
        id: String,
        reply: ReplyTo,
        signature: Option<String>,
        status: String,
        error: Option<String>,
    },
    /// Échec. `reason` : already_exists | invalid_key | need_proof | bad_proof | invalid_request |
    /// signer_unavailable | internal…
    Failed {
        id: String,
        reply: ReplyTo,
        reason: String,
    },
}

impl Event {
    pub fn reply(&self) -> &ReplyTo {
        match self {
            Event::AutoTrade { reply, .. }
            | Event::Deposit { reply, .. }
            | Event::Pong { reply, .. }
            | Event::WalletCreated { reply, .. }
            | Event::WalletImported { reply, .. }
            | Event::TransportKey { reply, .. }
            | Event::Nonce { reply, .. }
            | Event::PasskeyRegistered { reply, .. }
            | Event::RecoveryCodes { reply, .. }
            | Event::Done { reply, .. }
            | Event::Trade { reply, .. }
            | Event::Positions { reply, .. }
            | Event::Balances { reply, .. }
            | Event::Withdrawn { reply, .. }
            | Event::TotpSecret { reply, .. }
            | Event::Reclaimed { reply, .. }
            | Event::ReclaimQuotes { reply, .. }
            | Event::Failed { reply, .. } => reply,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_stable_pour_typescript() -> Result<(), serde_json::Error> {
        let cmd = Command::Ping {
            id: "abc".into(),
            reply: ReplyTo::Telegram {
                chat_id: "42".into(),
            },
            requested_at_ms: "1700000000000".into(),
        };
        let json = serde_json::to_string(&cmd)?;
        assert_eq!(
            json,
            r#"{"kind":"ping","id":"abc","reply":{"channel":"telegram","chat_id":"42"},"requested_at_ms":"1700000000000"}"#
        );
        assert_eq!(serde_json::from_str::<Command>(&json)?, cmd);
        Ok(())
    }

    #[test]
    fn refuse_un_message_inconnu() {
        assert!(serde_json::from_str::<Command>(r#"{"kind":"withdraw_all"}"#).is_err());
    }
}

/// Génère `constants.ts` : les constantes du protocole, côté TypeScript, depuis cette source unique.
#[cfg(test)]
mod export_constants {
    use super::*;

    #[test]
    fn exporte_les_constantes_typescript() -> std::io::Result<()> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/protocol/src/generated");
        std::fs::create_dir_all(&dir)?;
        let content = format!(
            "// Généré depuis crates/protocol/src/stream.rs par `cargo test`. Ne pas modifier à la main.\n\
             export const PROTOCOL_VERSION = {PROTOCOL_VERSION:?};\n\
             export const CMD_STREAM = {CMD_STREAM:?};\n\
             export const EVT_STREAM = {EVT_STREAM:?};\n\
             export const MSG_FIELD = {MSG_FIELD:?};\n\
             export const VERSION_FIELD = {VERSION_FIELD:?};\n\
             export const WITHDRAW_NETWORK_FEE = {WITHDRAW_NETWORK_FEE};\n"
        );
        std::fs::write(dir.join("constants.ts"), content)
    }
}
