//! Small, domain-independent mathematical primitives shared by HoneyForge components.

use std::{collections::HashSet, hash::Hash};

/// Returns `numerator / denominator`, with a defined zero result when the
/// denominator is zero.
pub fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Returns [`ratio`] expressed on a `0..=100` scale.
pub fn percentage(numerator: u64, denominator: u64) -> f64 {
    ratio(numerator, denominator) * 100.0
}

/// Computes `|A ∩ B| / |A ∪ B|` for two sets.
///
/// Two empty sets are considered identical and therefore have similarity
/// `1.0`; one empty and one non-empty set have similarity `0.0`.
pub fn jaccard_similarity<T: Eq + Hash>(left: &HashSet<T>, right: &HashSet<T>) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let intersection = left.intersection(right).count();
    let union = left.len() + right.len() - intersection;
    intersection as f64 / union as f64
}

/// Counts overlapping contiguous occurrences of `pattern` in `sequence`.
///
/// Matching uses the Knuth-Morris-Pratt algorithm, so runtime is linear in the
/// combined input size. An empty pattern has no occurrences.
pub fn count_overlapping_subsequences<T: Eq>(sequence: &[T], pattern: &[T]) -> usize {
    if pattern.is_empty() || sequence.len() < pattern.len() {
        return 0;
    }

    let prefix = prefix_table(pattern);
    let mut matched = 0;
    let mut count = 0;
    for item in sequence {
        while matched > 0 && item != &pattern[matched] {
            matched = prefix[matched - 1];
        }
        if item == &pattern[matched] {
            matched += 1;
        }
        if matched == pattern.len() {
            count += 1;
            matched = prefix[matched - 1];
        }
    }
    count
}

fn prefix_table<T: Eq>(pattern: &[T]) -> Vec<usize> {
    let mut prefix = vec![0; pattern.len()];
    let mut matched = 0;
    for index in 1..pattern.len() {
        while matched > 0 && pattern[index] != pattern[matched] {
            matched = prefix[matched - 1];
        }
        if pattern[index] == pattern[matched] {
            matched += 1;
            prefix[index] = matched;
        }
    }
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_close(actual: f64, expected: f64) {
        assert!((actual - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn ratios_and_percentages_define_empty_totals() {
        assert_close(ratio(3, 4), 0.75);
        assert_close(percentage(3, 4), 75.0);
        assert_close(ratio(0, 0), 0.0);
        assert_close(percentage(1, 0), 0.0);
    }

    #[test]
    fn jaccard_similarity_handles_overlap_and_empty_sets() {
        let left = HashSet::from(["a", "b", "c"]);
        let right = HashSet::from(["a", "b", "d"]);
        assert_close(jaccard_similarity(&left, &right), 0.5);

        let empty = HashSet::<&str>::new();
        assert_close(jaccard_similarity(&empty, &empty), 1.0);
        assert_close(jaccard_similarity(&empty, &left), 0.0);
    }

    #[test]
    fn overlapping_subsequences_use_linear_matching_semantics() {
        assert_eq!(count_overlapping_subsequences(b"aaaa", b"aa"), 3);
        assert_eq!(count_overlapping_subsequences(b"ababa", b"aba"), 2);
        assert_eq!(count_overlapping_subsequences(b"abc", b"d"), 0);
        assert_eq!(count_overlapping_subsequences(b"abc", b""), 0);
    }
}
