# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to [Semantic
Versioning].

## Unreleased

* Include a macOS hint in the message for the error that occurs if libsasl2
  is not found.

## [0.1.14] - 2020-12-20

* Introduce the `scram` feature to enable the SCRAM authentication method via
  the `--enable-scram` configure option. This feature requires linking against
  OpenSSL by way of the [openssl-sys] crate. For convenience, the new
  `openssl-vendored` feature re-exports the openssl-sys's crates `vendored`
  feature.

## [0.1.13] - 2020-12-15

* When linking against a system copy of libsasl2, permit manually specifying
  the search directory via the `SASL2_DIR`, `SASL2_LIB_DIR`, and
  `SASL2_INCLUDE_DIR` environment variables.

## [0.1.12] - 2020-07-08

* Introduce the `plain` feature to enable the PLAIN authentication method via
  the `--enable-plain` configure option.

## [0.1.11] - 2020-07-02

* When the `gssapi-vendored` feature is enabled, don't link against libresolv if
  the target system is DragonflyBSD, FreeBSD, NetBSD, or OpenBSD. Libresolv
  does not exist on these platforms, nor is it necessary; the relevant functions
  are part of libc directly.

## [0.1.10] - 2020-06-26

* Detect when the host system is DragonflyBSD, FreeBSD, NetBSD, or OpenBSD and
  invoke `gmake` instead of `make`, as libsasl2 is only compatible with GNU
  Make, and `make` on BSD systems defaults to BSD Make.

## [0.1.9] - 2020-04-28

* Don't fail cross-compilation on the check for GSSAPI SPNEGO availability.
  Instead conservatively disable it, but allow it to be manually enabled with an
  autoconf cache variable.

## [0.1.8] - 2020-04-28

* Update to v0.2.0 of [krb5-src] for cross-compilation support.

## [0.1.7] - 2020-04-28

* Ensure the GSSAPI plugin is position independent (i.e., compiled with `-fPIC`)
  when the `gssapi-vendored` feature is enabled.

## [0.1.6] - 2020-04-27

* Introduce the `gssapi-vendored` Cargo feature, which enables the GSSAPI plugin
  by building and statically linking against [libkrb5], MIT's Kerberos
  implementation.

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
[0.1.6]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.5...v0.1.6
[0.1.7]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.6...v0.1.7
[0.1.8]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.7...v0.1.8
[0.1.9]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.8...v0.1.9
[0.1.10]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.9...v0.1.10
[0.1.11]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.10...v0.1.11
[0.1.12]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.11...v0.1.12
[0.1.13]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.12...v0.1.13
[0.1.14]: https://github.com/MaterializeInc/rust-sasl/compare/v0.1.13...v0.1.14

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[crates-io-page]: https://crates.io/crates/sasl2-sys
[libkrb5]: https://web.mit.edu/kerberos/
