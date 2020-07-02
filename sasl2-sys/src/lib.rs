// Copyright Materialize, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License in the LICENSE file at the
// root of this repository, or online at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
#![doc(html_root_url = "https://docs.rs/sasl2-sys/0.1.11")]

//! Bindings to Cyrus SASL.
//!
//! This crate provides raw bindings to the [Cyrus SASL library][upstream],
//! libsasl2. Each module corresponds to a public header file in the [C
//! API][c-api].
//!
//! # Build configuration
//!
//! ## Vendored
//!
//! If the `vendored` Cargo feature is enabled, a bundled copy of libsasl2 will
//! be compiled and statically linked. The libsasl2 version will generally track
//! the latest upstream release. Note that the version number of this crate is
//! unrelated to the bundled version of libsasl2.
//!
//! sasl2-sys is currently bundling libsasl2 [v2.1.27].
//!
//! When configuring the bundled library, sasl2-sys is intentionally
//! conservative in the features it enables. All optional features are disabled
//! by default. The following Cargo features can be used to re-enable features
//! as necessary.
//!
//!   * **`gssapi-vendored`** enables the GSSAPI plugin (`--enable-gssapi`) by
//!      building and statically linking a copy of MIT's Kerberos implementation
//!      using the [krb5-src] crate.
//!
//! Note that specifying any of these features implies `vendored`.
//!
//! The eventual goal is to expose each libsasl2 feature behind a Cargo feature
//! of the same name. Pull requests on this front are welcomed.
//!
//! ## System
//!
//! Without the `vendored` Cargo feature, sasl2-sys will search for the libsasl2
//! library and headers in several standard locations. If the `pkg-config`
//! feature is enabled, as it is by default, pkg-config will be queried for the
//! location of the sasl2 library.
//!
//! When linking against the system-provided library, dynamic linking is
//! preferred unless the `SASL2_STATIC` variable is set.
//!
//! # Platform support
//!
//! Upstream supports [most major platforms][upstream-platforms], but sasl2-sys
//! is only tested on recent versions of Ubuntu, CentOS, and macOS. Patches that
//! improve support for other platforms are welcome.
//!
//! [c-api]: https://github.com/cyrusimap/cyrus-sasl/tree/master/include
//! [krb5-src]: https://github.com/MaterializeInc/rust-krb5-src
//! [upstream]: https://www.cyrusimap.org/sasl
//! [upstream-platforms]: https://www.cyrusimap.org/sasl/sasl/installation.html#supported-platforms
//! [v2.1.27]: https://github.com/cyrusimap/cyrus-sasl/releases/tag/cyrus-sasl-2.1.27

pub mod hmac_md5;
pub mod md5;
pub mod prop;
pub mod sasl;
pub mod saslplug;
pub mod saslutil;

/// Almagamates exports from all other modules.
pub mod prelude {
    pub use super::hmac_md5::*;
    pub use super::md5::*;
    pub use super::prop::*;
    pub use super::sasl::*;
    pub use super::saslplug::*;
    pub use super::saslutil::*;
}
