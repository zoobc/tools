<!-- SPDX-License-Identifier: MIT. Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci -->
# Publishing the packages

Every port is a package in its language's registry. One version tag releases them all.

## What a release is

1. Bump the version in the six places that carry one (they must agree): `ts/package.json`,
   `py/pyproject.toml`, `rust/Cargo.toml` (the workspace version), `kotlin/build.gradle.kts`,
   `perl/Makefile.PL` and `perl/lib/ZBC.pm` (`v0.1.0` form). PHP, Go and Swift take the version from the tag.
2. Commit, then tag twice and push the tags:

       git tag v0.1.0 && git tag go/v0.1.0 && git push origin v0.1.0 go/v0.1.0

   `v0.1.0` is what npm, PyPI, crates.io, Maven Central, CPAN, Packagist and SwiftPM see;
   `go/v0.1.0` is the same commit for the Go module, which lives in the `go/` directory
   (Go requires the directory prefix on the tag).
3. `.github/workflows/release.yml` runs on the `v*` tag: each job builds and tests its package,
   publishes it if the registry's secret is set, otherwise prints a notice and stays green; the last
   job attaches every built package, the C++ sources and the spec to a GitHub release. A job that
   was skipped for want of a secret can be re-run from the Actions page once the secret exists; the
   packages it publishes are the ones already built and attached.

## Where each package goes and what it needs

| Port | Registry, package | Secret(s) in the repository settings | One-time account work |
|------|-------------------|--------------------------------------|-----------------------|
| TypeScript / JS | npm, `@zoobc/tools` | `NPM_TOKEN` (granular access token, publish, packages of the `zoobc` org) | create the npm organisation `zoobc`, then the token |
| Python | PyPI, `zbc-tools` | `PYPI_API_TOKEN` (an API token; account-scoped for the first upload, then a project-scoped one) | a PyPI account |
| Rust | crates.io, `zbc` and `zbc-cli` | `CARGO_REGISTRY_TOKEN` (API token with `publish-new` and `publish-update`) | log in to crates.io with GitHub; verify the e-mail address |
| Kotlin | Maven Central, `foundation.zoobc:zbc` | `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD` (a Central Portal user token), `MAVEN_SIGNING_KEY` (ASCII-armoured GPG private key), `MAVEN_SIGNING_PASSWORD` | an account on central.sonatype.com; the namespace `foundation.zoobc`, verified by a DNS TXT record on `zoobc.foundation`; a GPG key pair whose public key is on a key server |
| Perl | CPAN, `ZBC` | `PAUSE_USERNAME`, `PAUSE_PASSWORD` | a PAUSE account (pause.perl.org, approved by hand within a day or two) |
| PHP | Packagist, `zoobc/zbc-tools` | none | a Packagist account; submit `https://github.com/zoobc/tools` once; Packagist then reads every tag itself (the GitHub hook is set on submission) |
| Go | the module `github.com/zoobc/tools/go` | none | none: `go get github.com/zoobc/tools/go@v0.1.0` after the `go/v0.1.0` tag |
| Swift | the package at the repository root | none | none: `.package(url: "https://github.com/zoobc/tools.git", from: "0.1.0")` |
| C++ | the sources, attached to the GitHub release | none | none |

Package names were checked free on every registry on 2026-09-16.

## Checked locally

`npm pack`, `python3 -m build`, `cargo publish --dry-run -p zbc`, `gradle publishToMavenLocal`
(jar, sources jar, pom, the spec inside the jar), `make dist` for Perl (its tests skip cleanly
outside the repository, where `spec/vectors` is not present) and `swift build` at the repository
root all succeed on the dev box; what has not been exercised is the upload itself, which needs the
accounts above.
