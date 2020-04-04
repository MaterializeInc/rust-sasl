# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to [Semantic
Versioning].

## [0.1.2] - 2020-04-03

* Pass the `--with-pic` configure option when building the vendored libsasl2 to
  enable position-independent code in static archives. This appears to be
  necessary for linking to succeed with some cross-compilation toolchains.

* Remove the dependency on autotools when building the vendored libsasl2
  by vendoring the source tarball directly, rather than using a Git submodule.

* Improve several build script error messages.

## [0.1.1] - 2020-04-03

* Fix [docs.rs build](https://docs.rs/sasl2-sys/0.1.1/sasl2-sys/).
* Include README contents on the [crates.io crate description][crates-io-page].

## [0.1.0] - 2020-04-03

Initial release.

[0.1.0]: https://github.com/MaterializeInc/rust-sasl/releases/tag/v0.1.0

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[crates-io-page]: https://crates.io/crates/sasl2-sys
