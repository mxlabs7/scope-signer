//! Protocole Scope : la SEULE source de vérité des messages échangés entre les blocs.
//!
//! - `stream` : messages JSON qui passent par Redis Streams (API, bot ↔ moteur).
//!   Les types TypeScript sont GÉNÉRÉS depuis ce fichier (`cargo test` → `packages/protocol`).
//! - `signer_frame` : trames binaires du canal privé moteur ↔ signer.
//! - `challenge` : défis des actions sensibles, signés par la passkey et recalculés par le signer.

pub mod challenge;
pub mod signer_frame;
pub mod stream;
