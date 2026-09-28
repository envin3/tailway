//! Guards the release bookkeeping: the version in Cargo.toml must have its
//! own entry in CHANGELOG.md, so a version is never bumped without notes.

const CHANGELOG: &str = include_str!("../CHANGELOG.md");

#[test]
fn the_changelog_describes_this_version() {
    let heading = format!("## [{}]", tailway::VERSION);
    assert!(
        CHANGELOG.lines().any(|line| line.starts_with(&heading)),
        "CHANGELOG.md has no \"{heading}\" section; add release notes for this version"
    );
    let link = format!("[{}]: ", tailway::VERSION);
    assert!(
        CHANGELOG.contains(&link),
        "CHANGELOG.md has no link for {}",
        tailway::VERSION
    );
}

#[test]
fn the_version_is_semantic() {
    let (core, pre) = tailway::VERSION
        .split_once('-')
        .unwrap_or((tailway::VERSION, ""));
    let parts: Vec<&str> = core.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "{} is not MAJOR.MINOR.PATCH",
        tailway::VERSION
    );
    assert!(parts.iter().all(|part| part.parse::<u32>().is_ok()));
    if tailway::VERSION.starts_with("0.") {
        assert!(
            pre.starts_with("alpha")
                || pre.starts_with("beta")
                || pre.starts_with("rc")
                || pre.is_empty(),
            "unexpected pre-release label {pre:?}"
        );
    }
}
