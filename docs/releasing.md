# Releasing

Tailway follows [Semantic Versioning](https://semver.org). The version in `Cargo.toml` is the only place the number is written; the binaries, `GET /v1/status`, and the console read it from there.

While Tailway is in alpha, versions are `0.MINOR.PATCH-alpha.N`:

- **`alpha.N`** goes up for each alpha release of the same version.
- **`MINOR`** goes up when a release changes settings, stored data, or behaviour in a way that needs attention on upgrade (in alpha, that can happen in any release).
- **`PATCH`** goes up for fixes only.

After alpha come `-beta.N`, `-rc.N`, and then plain `0.MINOR.PATCH`. `1.0.0` marks a stable configuration and data format.

## Making a release

1. Move the notes under **Unreleased** in `CHANGELOG.md` into a new section, `## [X.Y.Z-alpha.N] - YYYY-MM-DD`, and add its link at the bottom.
2. Set `version` in `Cargo.toml` to the same number and refresh the lockfile: `cargo update --workspace`.
3. Run `cargo test`. It fails if the changelog has no section for the new version.
4. Commit, then tag the commit: `git tag -a vX.Y.Z-alpha.N -m "Tailway X.Y.Z-alpha.N"`, and push the branch and the tag.
5. Build the images with the version as their tag: `IMAGE_TAG=X.Y.Z-alpha.N docker compose build`.

Test builds between releases use the commit's short hash as `IMAGE_TAG` instead.
