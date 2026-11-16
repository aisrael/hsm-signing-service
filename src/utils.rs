//! Small helpers that need no HSM.

use crate::hsm_backend::HsmBackendError;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;

/// Append a DER length. The lengths here are below 256.
fn push_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(length as u8);
    } else {
        out.push(0x81);
        out.push(length as u8);
    }
}

/// Append a DER INTEGER for an unsigned big-endian value.
fn push_integer(out: &mut Vec<u8>, value: &[u8]) {
    let first = value
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(value.len() - 1);
    let value = &value[first..];
    out.push(TAG_INTEGER);
    // A value with the high bit set needs a leading zero: DER integers are signed.
    if value[0] & 0x80 != 0 {
        push_length(out, value.len() + 1);
        out.push(0x00);
    } else {
        push_length(out, value.len());
    }
    out.extend_from_slice(value);
}

/// Convert the raw `r || s` signature of the HSM to a DER-encoded ECDSA
/// signature. `component_len` is the length in bytes of `r` and of `s` (32 for
/// P-256, 48 for P-384, 66 for P-521).
pub fn raw_to_der_signature(raw: &[u8], component_len: usize) -> Result<Vec<u8>, HsmBackendError> {
    if raw.len() != 2 * component_len {
        return Err(HsmBackendError::InvalidSignature(
            "the raw signature has the wrong length",
        ));
    }
    let (r, s) = raw.split_at(component_len);
    if r.iter().all(|b| *b == 0) || s.iter().all(|b| *b == 0) {
        return Err(HsmBackendError::InvalidSignature(
            "r and s must not be zero",
        ));
    }

    let mut body = Vec::with_capacity(2 * component_len + 8);
    push_integer(&mut body, r);
    push_integer(&mut body, s);

    let mut der = Vec::with_capacity(body.len() + 3);
    der.push(TAG_SEQUENCE);
    push_length(&mut der, body.len());
    der.extend_from_slice(&body);
    Ok(der)
}

/// Read a DER length (short form, or the long form with one byte).
fn read_length(input: &[u8]) -> Option<(usize, &[u8])> {
    let (first, rest) = input.split_first()?;
    match *first {
        length if length < 0x80 => Some((length as usize, rest)),
        0x81 => {
            let (length, rest) = rest.split_first()?;
            // The short form is the only valid form below 128.
            (*length >= 0x80).then_some((*length as usize, rest))
        }
        _ => None,
    }
}

/// Read one DER INTEGER and return its value as `component_len` bytes.
fn read_integer(input: &[u8], component_len: usize) -> Option<(Vec<u8>, &[u8])> {
    let (tag, rest) = input.split_first()?;
    if *tag != TAG_INTEGER {
        return None;
    }
    let (length, rest) = read_length(rest)?;
    if length == 0 || rest.len() < length {
        return None;
    }
    let (value, rest) = rest.split_at(length);
    // Negative values and extra leading zeros are not valid.
    if value[0] & 0x80 != 0 {
        return None;
    }
    let value = if value[0] == 0 && value.len() > 1 {
        if value[1] & 0x80 == 0 {
            return None;
        }
        &value[1..]
    } else {
        value
    };
    if value.iter().all(|b| *b == 0) || value.len() > component_len {
        return None;
    }
    let mut padded = vec![0; component_len - value.len()];
    padded.extend_from_slice(value);
    Some((padded, rest))
}

/// Convert a DER-encoded ECDSA signature to the raw `r || s` form that the HSM
/// expects. `component_len` is the length in bytes of `r` and of `s` (32 for
/// P-256, 48 for P-384, 66 for P-521). The check is strict: it accepts only the
/// canonical DER form, and `r` and `s` must not be zero.
pub fn der_to_raw_signature(der: &[u8], component_len: usize) -> Result<Vec<u8>, HsmBackendError> {
    let error = HsmBackendError::InvalidSignatureEncoding("not a valid DER ECDSA signature");
    let parse = || {
        let (tag, rest) = der.split_first()?;
        if *tag != TAG_SEQUENCE {
            return None;
        }
        let (length, rest) = read_length(rest)?;
        if rest.len() != length {
            return None;
        }
        let (r, rest) = read_integer(rest, component_len)?;
        let (s, rest) = read_integer(rest, component_len)?;
        rest.is_empty().then(|| [r, s].concat())
    };
    parse().ok_or(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw signature: `r` is all 0x01 and `s` is all 0x02.
    fn raw_signature(component_len: usize) -> Vec<u8> {
        [vec![0x01; component_len], vec![0x02; component_len]].concat()
    }

    #[test]
    fn converts_between_raw_and_der_for_every_curve_size() {
        for component_len in [32, 48, 66] {
            let raw = raw_signature(component_len);

            let der = raw_to_der_signature(&raw, component_len).unwrap();
            let back = der_to_raw_signature(&der, component_len).unwrap();

            assert_eq!(back, raw, "component length {component_len}");
            assert_eq!(back.len(), 2 * component_len);
        }
    }

    #[test]
    fn the_der_form_of_a_long_signature_uses_the_long_length_form() {
        // P-521 with the high bit set: 2 * (2 + 67) = 138 bytes in the sequence.
        let raw = [vec![0x80; 66], vec![0x7e; 66]].concat();

        let der = raw_to_der_signature(&raw, 66).unwrap();

        assert_eq!(&der[..2], &[0x30, 0x81]);
        assert_eq!(der_to_raw_signature(&der, 66).unwrap(), raw);
    }

    #[test]
    fn matches_a_known_der_signature() {
        // SEQUENCE { INTEGER 1, INTEGER 0x80 } with 1-byte components.
        let der = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80];

        assert_eq!(der_to_raw_signature(&der, 1).unwrap(), vec![0x01, 0x80]);
        assert_eq!(raw_to_der_signature(&[0x01, 0x80], 1).unwrap(), der);
    }

    #[test]
    fn keeps_leading_zero_bytes() {
        // In DER, a leading zero byte of `r` is dropped. The raw form must
        // still have `component_len` bytes for `r` and for `s`.
        let raw = [[0x00, 0x00, 0x01].as_slice(), &[0x03; 29], &[0x02; 32]].concat();
        assert_eq!(raw.len(), 64);

        let der = raw_to_der_signature(&raw, 32).unwrap();

        assert_eq!(der_to_raw_signature(&der, 32).unwrap(), raw);
    }

    #[test]
    fn keeps_a_high_bit_that_needs_a_zero_in_der() {
        let raw = [[0x80; 32], [0x7e; 32]].concat();

        let der = raw_to_der_signature(&raw, 32).unwrap();

        assert_eq!(der_to_raw_signature(&der, 32).unwrap(), raw);
    }

    #[test]
    fn raw_to_der_rejects_the_wrong_length() {
        let result = raw_to_der_signature(&[0x01; 63], 32);

        assert!(
            matches!(result, Err(HsmBackendError::InvalidSignature(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn raw_to_der_rejects_a_zero_component() {
        let raw = [vec![0x00; 32], vec![0x01; 32]].concat();

        let result = raw_to_der_signature(&raw, 32);

        assert!(
            matches!(result, Err(HsmBackendError::InvalidSignature(_))),
            "unexpected: {result:?}"
        );
    }

    fn assert_not_der(result: Result<Vec<u8>, HsmBackendError>) {
        assert!(
            matches!(result, Err(HsmBackendError::InvalidSignatureEncoding(_))),
            "unexpected: {result:?}"
        );
    }

    #[test]
    fn rejects_an_empty_input() {
        assert_not_der(der_to_raw_signature(&[], 32));
    }

    #[test]
    fn rejects_bytes_that_are_not_der() {
        assert_not_der(der_to_raw_signature(b"not a signature", 32));
    }

    #[test]
    fn rejects_a_raw_signature() {
        // The raw form is not DER. A caller that sends it by mistake gets an
        // error, not a wrong result.
        assert_not_der(der_to_raw_signature(&raw_signature(32), 32));
    }

    #[test]
    fn rejects_a_truncated_der_signature() {
        let der = raw_to_der_signature(&raw_signature(32), 32).unwrap();

        assert_not_der(der_to_raw_signature(&der[..der.len() - 1], 32));
    }

    #[test]
    fn rejects_a_der_signature_with_extra_bytes() {
        let mut der = raw_to_der_signature(&raw_signature(32), 32).unwrap();
        der.push(0x00);

        assert_not_der(der_to_raw_signature(&der, 32));
    }

    #[test]
    fn rejects_a_der_signature_with_a_zero_value() {
        // SEQUENCE { INTEGER 0, INTEGER 1 }. `r` and `s` must not be zero.
        let der = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];

        assert_not_der(der_to_raw_signature(&der, 32));
    }

    #[test]
    fn rejects_a_component_that_is_too_long_for_the_curve() {
        // A P-384 signature is not valid for P-256.
        let der = raw_to_der_signature(&raw_signature(48), 48).unwrap();

        assert_not_der(der_to_raw_signature(&der, 32));
    }

    #[test]
    fn rejects_a_negative_integer() {
        // SEQUENCE { INTEGER 0x80, INTEGER 1 }: the first integer is negative.
        let der = [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];

        assert_not_der(der_to_raw_signature(&der, 32));
    }

    #[test]
    fn rejects_an_integer_with_a_needless_leading_zero() {
        // SEQUENCE { INTEGER 0x00 0x01, INTEGER 1 }: not the shortest form.
        let der = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];

        assert_not_der(der_to_raw_signature(&der, 32));
    }
}
