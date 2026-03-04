//! Shannon entropy calculation for secret detection.
//!
//! This module implements the entropy calculation used by the high-entropy
//! string plugins, matching the Python `detect_secrets` implementation exactly.

/// Standard base64 charset used by `Base64HighEntropyString`.
///
/// Matches Python's `string.ascii_letters + string.digits + '+/' + '\\-_' + '='`.
pub const BASE64_CHARSET: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/\\-_=";

/// Standard hex charset used by `HexHighEntropyString`.
///
/// Matches Python's `string.hexdigits` (`'0123456789abcdefABCDEF'`).
pub const HEX_CHARSET: &str = "0123456789abcdefABCDEF";

/// Calculate Shannon entropy of `data` over the given `charset`.
///
/// For each character in `charset`, computes `p_x = count(char in data) / len(data)`
/// and accumulates `-p_x * log2(p_x)`.
///
/// Produces identical results to Python's
/// `HighEntropyStringsPlugin.calculate_shannon_entropy()`.
pub fn calculate_shannon_entropy(data: &str, charset: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0_f64;

    for ch in charset.chars() {
        let count = data.matches(ch).count() as f64;
        if count > 0.0 {
            let p_x = count / len;
            entropy += -p_x * p_x.log2();
        }
    }

    entropy
}

/// Calculate Shannon entropy for hex strings with numeric-only reduction.
///
/// When the input consists entirely of decimal digits (i.e. `int(data)` would
/// succeed in Python), applies a penalty: `entropy -= 1.2 / log2(len)`.
/// Single-character strings skip the reduction.
///
/// This matches Python's `HexHighEntropyString.calculate_shannon_entropy()`.
pub fn calculate_hex_shannon_entropy(data: &str) -> f64 {
    let entropy = calculate_shannon_entropy(data, HEX_CHARSET);

    if data.len() <= 1 {
        return entropy;
    }

    // Apply numeric-only reduction if all characters are ASCII digits
    if data.chars().all(|c| c.is_ascii_digit()) {
        entropy - 1.2 / (data.len() as f64).log2()
    } else {
        entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to assert floating-point values match within a tolerance.
    fn assert_entropy_eq(actual: f64, expected: f64) {
        let diff = (actual - expected).abs();
        assert!(
            diff < 1e-12,
            "entropy mismatch: actual={actual:.20}, expected={expected:.20}, diff={diff:.2e}"
        );
    }

    // ---- Base Shannon entropy (HEX charset) ----

    #[test]
    fn test_hex_entropy_all_same() {
        // "aaaaaa" over hex charset → 0.0
        assert_entropy_eq(calculate_shannon_entropy("aaaaaa", HEX_CHARSET), 0.0);
    }

    #[test]
    fn test_hex_entropy_md5_hash() {
        // Verified against Python
        assert_entropy_eq(
            calculate_shannon_entropy("2b00042f7481c7b056c4b410d28f33cf", HEX_CHARSET),
            3.54283779740341620013,
        );
    }

    #[test]
    fn test_hex_entropy_digits_only() {
        // "0123456789" → 3.32192809488736218171
        assert_entropy_eq(
            calculate_shannon_entropy("0123456789", HEX_CHARSET),
            3.32192809488736218171,
        );
    }

    #[test]
    fn test_hex_entropy_empty() {
        assert_entropy_eq(calculate_shannon_entropy("", HEX_CHARSET), 0.0);
    }

    #[test]
    fn test_hex_entropy_single_char() {
        assert_entropy_eq(calculate_shannon_entropy("a", HEX_CHARSET), 0.0);
    }

    #[test]
    fn test_hex_entropy_mixed() {
        // "abc123" → 2.58496250072115607566
        assert_entropy_eq(
            calculate_shannon_entropy("abc123", HEX_CHARSET),
            2.58496250072115607566,
        );
    }

    #[test]
    fn test_hex_entropy_uppercase_pairs() {
        // "AABB" → 1.0
        assert_entropy_eq(calculate_shannon_entropy("AABB", HEX_CHARSET), 1.0);
    }

    // ---- Base Shannon entropy (BASE64 charset) ----

    #[test]
    fn test_base64_entropy_short() {
        // "c3VwZXIgc2VjcmV0IHZhbHVl" → 3.80350885479767919506
        assert_entropy_eq(
            calculate_shannon_entropy("c3VwZXIgc2VjcmV0IHZhbHVl", BASE64_CHARSET),
            3.80350885479767919506,
        );
    }

    #[test]
    fn test_base64_entropy_long() {
        assert_entropy_eq(
            calculate_shannon_entropy(
                "c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5",
                BASE64_CHARSET,
            ),
            4.85865971244883354530,
        );
    }

    #[test]
    fn test_base64_entropy_hello_world() {
        assert_entropy_eq(
            calculate_shannon_entropy("Hello World", BASE64_CHARSET),
            2.53085715310995551519,
        );
    }

    // ---- Hex entropy with numeric reduction ----

    #[test]
    fn test_hex_reduced_digits_short() {
        // "0123456789" → 2.96069210009058458866
        assert_entropy_eq(
            calculate_hex_shannon_entropy("0123456789"),
            2.96069210009058458866,
        );
    }

    #[test]
    fn test_hex_reduced_digits_long() {
        // "01234567890123456789" → 3.04427423909565142424
        assert_entropy_eq(
            calculate_hex_shannon_entropy("01234567890123456789"),
            3.04427423909565142424,
        );
    }

    #[test]
    fn test_hex_reduced_no_penalty_with_letters() {
        // "12345a" is NOT all digits → no reduction, equals base entropy
        let base = calculate_shannon_entropy("12345a", HEX_CHARSET);
        assert_entropy_eq(calculate_hex_shannon_entropy("12345a"), base);
    }

    #[test]
    fn test_hex_reduced_single_char() {
        // Single char "0" → no reduction, equals base entropy
        let base = calculate_shannon_entropy("0", HEX_CHARSET);
        assert_entropy_eq(calculate_hex_shannon_entropy("0"), base);
    }

    #[test]
    fn test_hex_reduced_no_penalty_all_same() {
        // "aaaaaa" contains non-digits → no reduction
        let base = calculate_shannon_entropy("aaaaaa", HEX_CHARSET);
        assert_entropy_eq(calculate_hex_shannon_entropy("aaaaaa"), base);
    }

    #[test]
    fn test_hex_reduced_md5_no_penalty() {
        // md5 hash contains hex letters → no reduction
        let data = "2b00042f7481c7b056c4b410d28f33cf";
        let base = calculate_shannon_entropy(data, HEX_CHARSET);
        assert_entropy_eq(calculate_hex_shannon_entropy(data), base);
    }

    #[test]
    fn test_hex_reduced_all_nines() {
        // "999999" → -0.46422336868144992161 (can go negative)
        assert_entropy_eq(
            calculate_hex_shannon_entropy("999999"),
            -0.46422336868144992161,
        );
    }

    #[test]
    fn test_hex_reduced_hex_with_letters() {
        // "1234567890abcdef" is NOT all digits → no reduction, equals 4.0
        assert_entropy_eq(calculate_hex_shannon_entropy("1234567890abcdef"), 4.0);
    }

    // ---- Property tests ----

    #[test]
    fn test_length_dependency() {
        // Longer all-digit strings should have LESS penalty (closer to base entropy)
        let short = calculate_hex_shannon_entropy("0123456789");
        let long = calculate_hex_shannon_entropy("01234567890123456789");
        assert!(
            short < long,
            "longer all-digit string should have less penalty"
        );
    }

    #[test]
    fn test_digits_below_threshold() {
        // The goal: "0123456789" with hex reduction should be < 3.0
        assert!(calculate_hex_shannon_entropy("0123456789") < 3.0);
    }
}
