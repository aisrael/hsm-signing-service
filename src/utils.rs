//! Small helpers that need no HSM.

use p256::ecdsa::Signature;

use crate::hsm_backend::HsmBackendError;

/// Convert a DER-encoded ECDSA signature to the raw `r || s` form that the HSM
/// expects (64 bytes for P-256).
pub fn der_to_raw_signature(der: &[u8]) -> Result<Vec<u8>, HsmBackendError> {
    let signature = Signature::from_der(der).map_err(HsmBackendError::InvalidSignatureEncoding)?;
    Ok(signature.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw signature: `r` is 32 bytes of 0x01 and `s` is 32 bytes of 0x02.
    /// Both are valid P-256 scalars (not zero, below the group order).
    fn raw_signature() -> Vec<u8> {
        [[0x01; 32], [0x02; 32]].concat()
    }

    fn der_of(raw: &[u8]) -> Vec<u8> {
        Signature::from_slice(raw)
            .expect("the raw signature is valid")
            .to_der()
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn converts_a_der_signature_to_raw() {
        let raw = raw_signature();

        let result = der_to_raw_signature(&der_of(&raw)).expect("expected a raw signature");

        assert_eq!(result, raw);
    }

    #[test]
    fn the_raw_signature_has_64_bytes() {
        let result = der_to_raw_signature(&der_of(&raw_signature())).unwrap();

        assert_eq!(result.len(), 64);
    }

    #[test]
    fn keeps_leading_zero_bytes() {
        // In DER, a leading zero byte of `r` is dropped. The raw form must
        // still have 32 bytes for `r` and 32 bytes for `s`.
        let raw = [[0x00, 0x00, 0x01].as_slice(), &[0x03; 29], &[0x02; 32]].concat();
        assert_eq!(raw.len(), 64);

        let result = der_to_raw_signature(&der_of(&raw)).unwrap();

        assert_eq!(result, raw);
    }

    #[test]
    fn keeps_a_high_bit_that_needs_a_zero_in_der() {
        // A value with the high bit set gets an extra 0x00 byte in DER (the
        // DER integer is signed). The raw form must not keep that byte.
        let raw = [[0x80; 32], [0x7e; 32]].concat();

        let result = der_to_raw_signature(&der_of(&raw)).unwrap();

        assert_eq!(result, raw);
    }

    #[test]
    fn rejects_an_empty_input() {
        let result = der_to_raw_signature(&[]);

        assert!(
            matches!(result, Err(HsmBackendError::InvalidSignatureEncoding(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn rejects_bytes_that_are_not_der() {
        let result = der_to_raw_signature(b"not a signature");

        assert!(
            matches!(result, Err(HsmBackendError::InvalidSignatureEncoding(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn rejects_a_raw_signature() {
        // The raw form is not DER. A caller that sends it by mistake gets an
        // error, not a wrong result.
        let result = der_to_raw_signature(&raw_signature());

        assert!(
            matches!(result, Err(HsmBackendError::InvalidSignatureEncoding(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn rejects_a_truncated_der_signature() {
        let der = der_of(&raw_signature());

        let result = der_to_raw_signature(&der[..der.len() - 1]);

        assert!(
            matches!(result, Err(HsmBackendError::InvalidSignatureEncoding(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn rejects_a_der_signature_with_extra_bytes() {
        let mut der = der_of(&raw_signature());
        der.push(0x00);

        let result = der_to_raw_signature(&der);

        assert!(
            matches!(result, Err(HsmBackendError::InvalidSignatureEncoding(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn rejects_a_der_signature_with_a_zero_value() {
        // SEQUENCE { INTEGER 0, INTEGER 1 }. `r` and `s` must not be zero.
        let der = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];

        let result = der_to_raw_signature(&der);

        assert!(
            matches!(result, Err(HsmBackendError::InvalidSignatureEncoding(_))),
            "unexpected: {result:?}"
        );
    }
}
