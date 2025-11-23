//! Property-based tests for entropy calculation

use proptest::prelude::*;
use vulnera_secrets::domain::value_objects::Entropy;

proptest! {
    #[test]
    fn test_entropy_calculation_range(s in "[a-zA-Z0-9+/=]{20,100}") {
        let entropy = Entropy::shannon_entropy(&s);
        prop_assert!(entropy >= 0.0);
        prop_assert!(entropy <= 8.0);
    }

    #[test]
    fn test_base64_like_detection(s in "[a-zA-Z0-9+/]{20,100}") {
        // Ensure length is multiple of 4 for valid base64 check
        let pad_len = (4 - (s.len() % 4)) % 4;
        let padded = format!("{}{}", s, "=".repeat(pad_len));
        
        prop_assert!(Entropy::is_base64_like(&padded));
    }

    #[test]
    fn test_url_safe_base64_like_detection(s in "[a-zA-Z0-9_-]{20,100}") {
        // Ensure length is multiple of 4 for valid base64 check
        let pad_len = (4 - (s.len() % 4)) % 4;
        let padded = format!("{}{}", s, "=".repeat(pad_len));
        
        prop_assert!(Entropy::is_base64_like(&padded));
    }
    
    #[test]
    fn test_hex_like_detection(s in "[a-fA-F0-9]{20,100}") {
        prop_assert!(Entropy::is_hex_like(&s));
    }
}
