use super::prometheus::{Family, seconds};

#[test]
fn label_values_are_escaped() {
    let mut out = String::new();
    Family::new(&mut out, "m", "gauge", "help").sample(
        "m",
        &[("description", "say \"hi\"\\\n")],
        1,
    );
    assert!(
        out.ends_with("m{description=\"say \\\"hi\\\"\\\\\\n\"} 1\n"),
        "{out}"
    );
    assert!(out.starts_with("# HELP m help\n# TYPE m gauge\n"));
}

#[test]
fn seconds_keep_milliseconds() {
    assert_eq!(seconds(1_700_000_000_123), "1700000000.123");
    assert_eq!(seconds(5), "0.005");
}
