# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to [Semantic
Versioning].

## [0.1.5] - 2020-04-25

* Use libc types rather than Rust types for constants (e.g., `libc::c_int`
  rather than `i32`) to reduce the number of casts required when passing those
  constants to other sasl2-sys functions.

  **This is a backwards-incompatible change.**

## [0.1.4] - 2020-04-10

* Don't build documentation and tests. This saves time and avoids depending on
  somewhat esoteric tools like nroff.

## [0.1.3] - 2020-04-08

* Disable maintainer mode in the libsasl2 build system. Because Git does not
  preserve timestamps on source files, `configure` can look out-of-date with
  respect to `configure.ac` (et al.), and so `make` will try to rebuild
  `configure`, which requires autotools. Disabling maintainer mode ensures Make
  will never invoke autotools, even if the autotools files look out of date.

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

## 0.1.0 - 2020-04-03

Initial release.

[0.1.1]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.0...v0.1.1
[0.1.2]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.1...v0.1.2
[0.1.3]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.2...v0.1.3
[0.1.4]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.3...v0.1.4
[0.1.5]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.4...v0.1.5

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[crates-io-page]: https://crates.io/crates/sasl2-sys
