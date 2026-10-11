use pritvoryashka::ssh::auth::constant_time_eq;

#[test]
fn password_comparison_handles_equal_unequal_and_different_lengths() {
    assert!(constant_time_eq(b"correct horse", b"correct horse"));
    assert!(!constant_time_eq(b"correct horse", b"correct house"));
    assert!(!constant_time_eq(b"short", b"longer"));
}
