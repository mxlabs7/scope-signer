//! Vérification de passkeys (WebAuthn) PAR LE SIGNER, sans faire confiance à l'API.
//!
//! Le signer vérifie lui-même : le site (rpId), l'origine, le défi exact (qu'il recalcule),
//! la présence ET la vérification de l'utilisateur (empreinte, Face ID, PIN), le compteur
//! (passkey clonée) et la signature. Algorithmes : ES256 (P-256) et EdDSA (Ed25519).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::Value;
use p256::ecdsa::signature::Verifier as _;
pub use scope_protocol::signer_frame::Assertion;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
pub enum WebauthnError {
    BadKey,
    BadClientData,
    WrongType,
    WrongChallenge,
    WrongOrigin,
    BadAuthenticatorData,
    WrongRpId,
    UserNotPresent,
    UserNotVerified,
    /// Le compteur n'a pas augmenté : passkey probablement clonée.
    CounterReplay,
    BadSignature,
}

/// Clé publique d'une passkey, décodée depuis le format COSE.
pub enum CoseKey {
    Es256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

fn int(v: &Value) -> Option<i128> {
    v.as_integer().map(i128::from)
}

/// Décode une clé COSE (format stocké par les navigateurs). Refuse tout ce qui n'est pas ES256 ou EdDSA.
pub fn parse_cose(bytes: &[u8]) -> Result<CoseKey, WebauthnError> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| WebauthnError::BadKey)?;
    let map = value.as_map().ok_or(WebauthnError::BadKey)?;
    let get = |k: i128| {
        map.iter()
            .find(|(key, _)| int(key) == Some(k))
            .map(|(_, v)| v)
    };
    let bytes_of = |k: i128| {
        get(k)
            .and_then(Value::as_bytes)
            .ok_or(WebauthnError::BadKey)
    };

    match (
        get(1).and_then(int),
        get(3).and_then(int),
        get(-1).and_then(int),
    ) {
        // kty EC2, alg ES256, courbe P-256
        (Some(2), Some(-7), Some(1)) => {
            let (x, y) = (bytes_of(-2)?, bytes_of(-3)?);
            if x.len() != 32 || y.len() != 32 {
                return Err(WebauthnError::BadKey);
            }
            let sec1 = [&[0x04u8][..], x, y].concat();
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map(CoseKey::Es256)
                .map_err(|_| WebauthnError::BadKey)
        }
        // kty OKP, alg EdDSA, courbe Ed25519
        (Some(1), Some(-8), Some(6)) => {
            let x: [u8; 32] = bytes_of(-2)?
                .as_slice()
                .try_into()
                .map_err(|_| WebauthnError::BadKey)?;
            ed25519_dalek::VerifyingKey::from_bytes(&x)
                .map(CoseKey::Ed25519)
                .map_err(|_| WebauthnError::BadKey)
        }
        _ => Err(WebauthnError::BadKey),
    }
}

pub struct RelyingParty {
    pub id: String,
    pub origins: Vec<String>,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin")]
    cross_origin: Option<bool>,
}

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

/// Vérifie une assertion pour un défi PRÉCIS. Renvoie le nouveau compteur à enregistrer.
pub fn verify(
    rp: &RelyingParty,
    key: &CoseKey,
    stored_counter: u32,
    a: &Assertion,
    expected_challenge: &[u8],
) -> Result<u32, WebauthnError> {
    let client: ClientData =
        serde_json::from_slice(&a.client_data_json).map_err(|_| WebauthnError::BadClientData)?;
    if client.kind != "webauthn.get" {
        return Err(WebauthnError::WrongType);
    }
    if client.challenge != URL_SAFE_NO_PAD.encode(expected_challenge) {
        return Err(WebauthnError::WrongChallenge);
    }
    if !rp.origins.contains(&client.origin) || client.cross_origin == Some(true) {
        return Err(WebauthnError::WrongOrigin);
    }

    let ad = &a.authenticator_data;
    if ad.len() < 37 {
        return Err(WebauthnError::BadAuthenticatorData);
    }
    if ad[..32] != Sha256::digest(rp.id.as_bytes())[..] {
        return Err(WebauthnError::WrongRpId);
    }
    if ad[32] & FLAG_UP == 0 {
        return Err(WebauthnError::UserNotPresent);
    }
    if ad[32] & FLAG_UV == 0 {
        return Err(WebauthnError::UserNotVerified);
    }
    let counter = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]);
    // Les passkeys synchronisées (iCloud, Google) ont toujours 0 : le contrôle ne joue que si un compteur existe.
    if (stored_counter > 0 || counter > 0) && counter <= stored_counter {
        return Err(WebauthnError::CounterReplay);
    }

    let signed = [
        ad.as_slice(),
        Sha256::digest(&a.client_data_json).as_slice(),
    ]
    .concat();
    let ok = match key {
        CoseKey::Es256(k) => p256::ecdsa::Signature::from_der(&a.signature)
            .is_ok_and(|s| k.verify(&signed, &s).is_ok()),
        CoseKey::Ed25519(k) => <[u8; 64]>::try_from(a.signature.as_slice()).is_ok_and(|s| {
            k.verify_strict(&signed, &ed25519_dalek::Signature::from_bytes(&s))
                .is_ok()
        }),
    };
    if !ok {
        return Err(WebauthnError::BadSignature);
    }
    Ok(counter)
}

#[cfg(test)]
pub mod testing {
    //! Faux authentificateur (ES256) pour les tests du signer.
    use super::*;
    use p256::ecdsa::signature::Signer as _;

    pub const RP_ID: &str = "localhost";
    pub const ORIGIN: &str = "http://localhost:5173";

    pub fn rp() -> RelyingParty {
        RelyingParty {
            id: RP_ID.into(),
            origins: vec![ORIGIN.into()],
        }
    }

    #[derive(Default, Clone)]
    pub struct Tamper {
        pub origin: Option<String>,
        pub rp_id: Option<String>,
        pub kind: Option<String>,
        pub no_uv: bool,
        pub counter: Option<u32>,
    }

    pub struct Device {
        key: p256::ecdsa::SigningKey,
        pub credential_id: Vec<u8>,
        counter: u32,
    }

    impl Device {
        pub fn new(seed: u8) -> Self {
            let key = p256::ecdsa::SigningKey::from_slice(&[seed.max(1); 32])
                .unwrap_or_else(|_| unreachable!());
            Self {
                key,
                credential_id: vec![seed; 16],
                counter: 0,
            }
        }

        /// Clé publique au format COSE (comme l'enregistre le navigateur).
        pub fn cose(&self) -> Vec<u8> {
            let point = self.key.verifying_key().to_sec1_point(false);
            let bytes = point.as_bytes();
            let map = Value::Map(vec![
                (Value::from(1), Value::from(2)),
                (Value::from(3), Value::from(-7)),
                (Value::from(-1), Value::from(1)),
                (Value::from(-2), Value::Bytes(bytes[1..33].to_vec())),
                (Value::from(-3), Value::Bytes(bytes[33..65].to_vec())),
            ]);
            let mut out = Vec::new();
            ciborium::into_writer(&map, &mut out).unwrap_or_else(|_| unreachable!());
            out
        }

        pub fn assert(&mut self, challenge: &[u8], t: &Tamper) -> Assertion {
            self.counter += 1;
            let mut ad = Sha256::digest(t.rp_id.as_deref().unwrap_or(RP_ID).as_bytes()).to_vec();
            ad.push(FLAG_UP | if t.no_uv { 0 } else { FLAG_UV });
            ad.extend_from_slice(&t.counter.unwrap_or(self.counter).to_be_bytes());
            let client = serde_json::json!({
                "type": t.kind.as_deref().unwrap_or("webauthn.get"),
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "origin": t.origin.as_deref().unwrap_or(ORIGIN),
            })
            .to_string()
            .into_bytes();
            let signed = [ad.as_slice(), Sha256::digest(&client).as_slice()].concat();
            let sig: p256::ecdsa::Signature = self.key.sign(&signed);
            Assertion {
                credential_id: self.credential_id.clone(),
                authenticator_data: ad,
                client_data_json: client,
                signature: sig.to_der().as_bytes().to_vec(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn check(device: &mut Device, t: Tamper, stored: u32) -> Result<u32, WebauthnError> {
        let key = parse_cose(&device.cose())?;
        let a = device.assert(b"defi", &t);
        verify(&rp(), &key, stored, &a, b"defi")
    }

    #[test]
    fn accepte_une_assertion_valide() {
        assert_eq!(check(&mut Device::new(1), Tamper::default(), 0), Ok(1));
    }

    #[test]
    fn refuse_un_autre_site_ou_une_autre_origine() {
        let mut d = Device::new(2);
        let phishing = Tamper {
            origin: Some("https://scope-login.com".into()),
            ..Tamper::default()
        };
        assert_eq!(check(&mut d, phishing, 0), Err(WebauthnError::WrongOrigin));
        let other_rp = Tamper {
            rp_id: Some("evil.com".into()),
            ..Tamper::default()
        };
        assert_eq!(check(&mut d, other_rp, 0), Err(WebauthnError::WrongRpId));
    }

    #[test]
    fn exige_la_verification_de_l_utilisateur() {
        let t = Tamper {
            no_uv: true,
            ..Tamper::default()
        };
        assert_eq!(
            check(&mut Device::new(3), t, 0),
            Err(WebauthnError::UserNotVerified)
        );
    }

    #[test]
    fn refuse_un_autre_defi_et_un_mauvais_type() {
        let mut d = Device::new(4);
        let key = parse_cose(&d.cose()).unwrap_or_else(|_| unreachable!());
        let a = d.assert(b"retrait de 1 SOL vers A", &Tamper::default());
        assert_eq!(
            verify(&rp(), &key, 0, &a, b"retrait de 1 SOL vers PIRATE"),
            Err(WebauthnError::WrongChallenge)
        );
        let create = Tamper {
            kind: Some("webauthn.create".into()),
            ..Tamper::default()
        };
        assert_eq!(check(&mut d, create, 0), Err(WebauthnError::WrongType));
    }

    #[test]
    fn detecte_une_passkey_clonee() {
        let t = Tamper {
            counter: Some(5),
            ..Tamper::default()
        };
        assert_eq!(
            check(&mut Device::new(5), t, 10),
            Err(WebauthnError::CounterReplay)
        );
    }

    #[test]
    fn accepte_les_passkeys_synchronisees_sans_compteur() {
        let t = Tamper {
            counter: Some(0),
            ..Tamper::default()
        };
        assert_eq!(check(&mut Device::new(6), t, 0), Ok(0));
    }

    #[test]
    fn refuse_une_signature_d_une_autre_cle() {
        let mut victim = Device::new(7);
        let mut thief = Device::new(8);
        let key = parse_cose(&victim.cose()).unwrap_or_else(|_| unreachable!());
        let forged = thief.assert(b"defi", &Tamper::default());
        assert_eq!(
            verify(&rp(), &key, 0, &forged, b"defi"),
            Err(WebauthnError::BadSignature)
        );
        let mut a = victim.assert(b"defi", &Tamper::default());
        a.authenticator_data[36] ^= 1; // données modifiées après signature
        assert_eq!(
            verify(&rp(), &key, 0, &a, b"defi"),
            Err(WebauthnError::BadSignature)
        );
    }

    #[test]
    fn refuse_les_cles_et_donnees_mal_formees_sans_paniquer() {
        for junk in [vec![], vec![0xff; 10], vec![0xa0], b"pas du cbor".to_vec()] {
            assert!(parse_cose(&junk).is_err());
        }
        let mut d = Device::new(9);
        let key = parse_cose(&d.cose()).unwrap_or_else(|_| unreachable!());
        let mut a = d.assert(b"defi", &Tamper::default());
        a.client_data_json = b"{".to_vec();
        assert_eq!(
            verify(&rp(), &key, 0, &a, b"defi"),
            Err(WebauthnError::BadClientData)
        );
        let mut a = d.assert(b"defi", &Tamper::default());
        a.authenticator_data.truncate(10);
        assert_eq!(
            verify(&rp(), &key, 0, &a, b"defi"),
            Err(WebauthnError::BadAuthenticatorData)
        );
    }
}
