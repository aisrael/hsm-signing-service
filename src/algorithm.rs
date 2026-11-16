//! The signing algorithms of the service, and what each one needs from the HSM.

use cryptoki::mechanism::Mechanism;
use cryptoki::object::KeyType;
use serde::Deserialize;
use serde::Serialize;

/// DER of the OID of the curve prime256v1 (P-256).
const EC_PARAMS_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// DER of the OID of the curve secp384r1 (P-384).
const EC_PARAMS_P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
/// DER of the OID of the curve secp521r1 (P-521).
const EC_PARAMS_P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

/// The algorithm to use for signing. The HSM hashes the payload in every case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// ECDSA on P-256 with SHA-256. The signature is in DER form.
    #[serde(rename = "ECDSA_P256_SHA256")]
    EcdsaP256Sha256,
    /// ECDSA on P-384 with SHA-384. The signature is in DER form.
    #[serde(rename = "ECDSA_P384_SHA384")]
    EcdsaP384Sha384,
    /// ECDSA on P-521 with SHA-512. The signature is in DER form.
    #[serde(rename = "ECDSA_P521_SHA512")]
    EcdsaP521Sha512,
    /// RSA PKCS#1 v1.5 with SHA-256. The signature is the raw bytes.
    #[serde(rename = "RSA_PKCS1_SHA256")]
    RsaPkcs1Sha256,
}

impl Algorithm {
    /// The name of the algorithm in the API (for example `ECDSA_P256_SHA256`).
    /// Also used as the `algorithm` attribute of the spans.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::EcdsaP256Sha256 => "ECDSA_P256_SHA256",
            Algorithm::EcdsaP384Sha384 => "ECDSA_P384_SHA384",
            Algorithm::EcdsaP521Sha512 => "ECDSA_P521_SHA512",
            Algorithm::RsaPkcs1Sha256 => "RSA_PKCS1_SHA256",
        }
    }

    /// The PKCS#11 mechanism that signs and verifies for this algorithm.
    pub fn mechanism(self) -> Mechanism<'static> {
        match self {
            Algorithm::EcdsaP256Sha256 => Mechanism::EcdsaSha256,
            Algorithm::EcdsaP384Sha384 => Mechanism::EcdsaSha384,
            Algorithm::EcdsaP521Sha512 => Mechanism::EcdsaSha512,
            Algorithm::RsaPkcs1Sha256 => Mechanism::Sha256RsaPkcs,
        }
    }

    /// The type of key that the algorithm needs.
    pub fn key_type(self) -> KeyType {
        match self {
            Algorithm::EcdsaP256Sha256
            | Algorithm::EcdsaP384Sha384
            | Algorithm::EcdsaP521Sha512 => KeyType::EC,
            Algorithm::RsaPkcs1Sha256 => KeyType::RSA,
        }
    }

    /// For an EC algorithm, the DER of the curve (`CKA_EC_PARAMS`) that the key
    /// must have.
    pub fn ec_params(self) -> Option<&'static [u8]> {
        match self {
            Algorithm::EcdsaP256Sha256 => Some(EC_PARAMS_P256),
            Algorithm::EcdsaP384Sha384 => Some(EC_PARAMS_P384),
            Algorithm::EcdsaP521Sha512 => Some(EC_PARAMS_P521),
            Algorithm::RsaPkcs1Sha256 => None,
        }
    }

    /// For an ECDSA algorithm, the length in bytes of `r` and of `s` in the
    /// raw signature of the HSM. `None` for the other algorithms.
    pub fn ecdsa_component_len(self) -> Option<usize> {
        match self {
            Algorithm::EcdsaP256Sha256 => Some(32),
            Algorithm::EcdsaP384Sha384 => Some(48),
            Algorithm::EcdsaP521Sha512 => Some(66),
            Algorithm::RsaPkcs1Sha256 => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_names_in_json_are_stable() {
        let names = [
            (Algorithm::EcdsaP256Sha256, "\"ECDSA_P256_SHA256\""),
            (Algorithm::EcdsaP384Sha384, "\"ECDSA_P384_SHA384\""),
            (Algorithm::EcdsaP521Sha512, "\"ECDSA_P521_SHA512\""),
            (Algorithm::RsaPkcs1Sha256, "\"RSA_PKCS1_SHA256\""),
        ];
        for (algorithm, name) in names {
            assert_eq!(serde_json::to_string(&algorithm).unwrap(), name);
            assert_eq!(serde_json::from_str::<Algorithm>(name).unwrap(), algorithm);
        }
    }

    #[test]
    fn name_is_the_name_in_json() {
        for algorithm in [
            Algorithm::EcdsaP256Sha256,
            Algorithm::EcdsaP384Sha384,
            Algorithm::EcdsaP521Sha512,
            Algorithm::RsaPkcs1Sha256,
        ] {
            let json = serde_json::to_string(&algorithm).unwrap();
            assert_eq!(json, format!("\"{}\"", algorithm.name()));
        }
    }

    #[test]
    fn an_unknown_name_is_rejected() {
        assert!(serde_json::from_str::<Algorithm>("\"ED25519\"").is_err());
    }

    #[test]
    fn only_the_ecdsa_algorithms_have_a_curve_and_a_component_length() {
        assert!(Algorithm::EcdsaP384Sha384.ec_params().is_some());
        assert_eq!(Algorithm::EcdsaP521Sha512.ecdsa_component_len(), Some(66));
        assert!(Algorithm::RsaPkcs1Sha256.ec_params().is_none());
        assert!(Algorithm::RsaPkcs1Sha256.ecdsa_component_len().is_none());
    }
}
