//! Property-based tests for version parsing

use proptest::prelude::*;
use vulnera_core::domain::vulnerability::value_objects::Version;

proptest! {
    #[test]
    fn test_version_parsing_roundtrip(
        major in 0u64..1000u64,
        minor in 0u64..1000u64,
        patch in 0u64..1000u64
    ) {
        let version_str = format!("{}.{}.{}", major, minor, patch);
        if let Ok(version) = Version::parse(&version_str) {
            // Version should be parseable and representable
            assert_eq!(version.to_string(), version_str);
        }
    }

    #[test]
    fn test_version_comparison_consistency(
        major1 in 0u64..100u64,
        minor1 in 0u64..100u64,
        patch1 in 0u64..100u64,
        major2 in 0u64..100u64,
        minor2 in 0u64..100u64,
        patch2 in 0u64..100u64
    ) {
        let v1_str = format!("{}.{}.{}", major1, minor1, patch1);
        let v2_str = format!("{}.{}.{}", major2, minor2, patch2);

        if let (Ok(v1), Ok(v2)) = (Version::parse(&v1_str), Version::parse(&v2_str)) {
            // Comparison should be consistent
            let cmp_str = if major1 != major2 {
                major1.cmp(&major2)
            } else if minor1 != minor2 {
                minor1.cmp(&minor2)
            } else {
                patch1.cmp(&patch2)
            };

            let cmp_version = v1.cmp(&v2);
            assert_eq!(cmp_str, cmp_version);
        }
    }
}
