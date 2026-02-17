//! Sharding utilities for distributed analysis execution.
//!
//! Provides deterministic partitioning of files into balanced shards that can be
//! dispatched across worker pools or remote executors.

use std::path::PathBuf;

/// A file candidate with optional estimated size for balancing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardCandidate {
    pub path: PathBuf,
    pub estimated_size_bytes: u64,
}

impl ShardCandidate {
    pub fn new(path: impl Into<PathBuf>, estimated_size_bytes: u64) -> Self {
        Self {
            path: path.into(),
            estimated_size_bytes,
        }
    }
}

/// A deterministic shard payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkShard {
    pub id: usize,
    pub total_size_bytes: u64,
    pub files: Vec<PathBuf>,
}

/// Build approximately balanced shards using a deterministic best-fit strategy.
///
/// - `max_shards`: maximum number of shards to generate (>0)
/// - returns empty vector when input is empty
pub fn build_balanced_shards(
    mut candidates: Vec<ShardCandidate>,
    max_shards: usize,
) -> Vec<WorkShard> {
    if candidates.is_empty() || max_shards == 0 {
        return Vec::new();
    }

    // Deterministic ordering: largest files first, then lexical path tie-breaker.
    candidates.sort_by(|a, b| {
        b.estimated_size_bytes
            .cmp(&a.estimated_size_bytes)
            .then_with(|| a.path.cmp(&b.path))
    });

    let shard_count = max_shards.min(candidates.len()).max(1);
    let mut shards: Vec<WorkShard> = (0..shard_count)
        .map(|id| WorkShard {
            id,
            total_size_bytes: 0,
            files: Vec::new(),
        })
        .collect();

    for candidate in candidates {
        // Pick lightest shard; tie-break on shard id for deterministic placement.
        let target_idx = shards
            .iter()
            .enumerate()
            .min_by(|(_, lhs), (_, rhs)| {
                lhs.total_size_bytes
                    .cmp(&rhs.total_size_bytes)
                    .then_with(|| lhs.id.cmp(&rhs.id))
            })
            .map(|(idx, _)| idx)
            .unwrap_or(0);

        let shard = &mut shards[target_idx];
        shard.total_size_bytes = shard
            .total_size_bytes
            .saturating_add(candidate.estimated_size_bytes);
        shard.files.push(candidate.path);
    }

    shards
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_balanced_shards_is_deterministic() {
        let input = vec![
            ShardCandidate::new("a.py", 120),
            ShardCandidate::new("b.py", 100),
            ShardCandidate::new("c.py", 80),
            ShardCandidate::new("d.py", 60),
        ];

        let left = build_balanced_shards(input.clone(), 2);
        let right = build_balanced_shards(input, 2);

        assert_eq!(left, right);
        assert_eq!(left.len(), 2);
    }

    #[test]
    fn build_balanced_shards_spreads_large_items() {
        let input = vec![
            ShardCandidate::new("big-1.py", 1_000),
            ShardCandidate::new("big-2.py", 900),
            ShardCandidate::new("small-1.py", 100),
            ShardCandidate::new("small-2.py", 100),
        ];

        let shards = build_balanced_shards(input, 2);
        assert_eq!(shards.len(), 2);

        let delta = shards[0]
            .total_size_bytes
            .abs_diff(shards[1].total_size_bytes);
        assert!(delta <= 200, "Expected reasonable balancing, delta={delta}");
    }

    #[test]
    fn build_balanced_shards_handles_edge_inputs() {
        assert!(build_balanced_shards(Vec::new(), 3).is_empty());

        let single = build_balanced_shards(vec![ShardCandidate::new("one.rs", 10)], 8);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].files, vec![PathBuf::from("one.rs")]);
        assert_eq!(single[0].total_size_bytes, 10);
    }
}
