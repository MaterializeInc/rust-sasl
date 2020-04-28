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

use std::env;
use std::ffi::OsString;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use duct::cmd;

struct Metadata {
    host: String,
    target: String,
    want_static: Option<bool>,
    out_dir: PathBuf,
}

fn main() {
    println!("cargo:rerun-if-env-changed=SASL2_STATIC");

    let metadata = Metadata {
        host: env::var("HOST").unwrap(),
        target: env::var("TARGET").unwrap(),
        want_static: env::var_os("SASL2_STATIC").map(|v| v != "0"),
        out_dir: env::var("OUT_DIR").unwrap().into(),
    };

    if cfg!(feature = "vendored") {
        build_sasl(&metadata)
    } else {
        find_sasl(&metadata)
    };
}

fn build_sasl(metadata: &Metadata) {
    let src_dir = metadata.out_dir.join("sasl2");
    if !src_dir.exists() {
        // We're not allowed to build in-tree directly, as ~/.cargo/registry is
        // globally shared, but sasl doesn't seem to support out-of-tree builds.
        // Work around the issue by copying sasl into OUT_DIR, and building
        // inside of *that* tree.
        cmd!("cp", "-R", "sasl2", &src_dir)
            .run()
            .expect("failed making copy of sasl2 tree");
    }

    let install_dir = metadata.out_dir.join("install");
    let mut configure_args = vec![
        format!("--prefix={}", install_dir.display()),
        "--enable-static".into(),
        "--disable-shared".into(),
        "--disable-sample".into(),
        "--disable-checkapop".into(),
        "--disable-cram".into(),
        "--disable-scram".into(),
        "--disable-digest".into(),
        "--disable-otp".into(),
        #[cfg(feature = "gssapi-vendored")]
        format!("--enable-gssapi={}", krb5_src::INSTALL_DIR),
        #[cfg(not(feature = "gssapi-vendored"))]
        "--disable-gssapi".into(),
        "--disable-plain".into(),
        "--disable-anon".into(),
        "--with-dblib=none".into(),
        "--with-pic".into(),
    ];
    if metadata.target.contains("darwin") {
        configure_args.push("--disable-macos-framework".into());
    }
    if metadata.host != metadata.target {
        configure_args.push(format!("--host={}", metadata.target));
    }
    cmd(src_dir.join("configure"), &configure_args)
        .dir(&src_dir)
        .run()
        .expect("configure failed");

    let mut make_flags = OsString::new();
    let mut make_args = vec![];
    if let Ok(s) = env::var("NUM_JOBS") {
        match env::var_os("CARGO_MAKEFLAGS") {
            // Only do this on non-windows and non-bsd
            // On Windows, we could be invoking make instead of
            // mingw32-make which doesn't work with our jobserver
            // bsdmake also does not work with our job server
            Some(ref s)
                if !(cfg!(windows)
                    || cfg!(target_os = "openbsd")
                    || cfg!(target_os = "netbsd")
                    || cfg!(target_os = "freebsd")
                    || cfg!(target_os = "bitrig")
                    || cfg!(target_os = "dragonflybsd")) =>
            {
                make_flags = s.clone()
            }

            // This looks like `make`, let's hope it understands `-jN`.
            _ => make_args.push(format!("-j{}", s)),
        }
    }

    // Try very hard to only build the components we need. We want to run
    // `cd lib && make install`, but that Makefile is incorrectly dependent
    // on targets in `include` and `common`, so build those directories first.
    for sub_dir in &["include", "common", "lib", "sasldb", "plugins"] {
        cmd!("make", "install")
            .dir(src_dir.join(sub_dir))
            .env("MAKEFLAGS", &make_flags)
            .run()
            .expect("make failed");
    }

    validate_headers(&[install_dir.join("include")]);

    println!(
        "cargo:rustc-link-search=native={}",
        install_dir.join("lib").display(),
    );
    println!("cargo:rustc-link-lib=static=sasl2");
    println!("cargo:root={}", install_dir.display());

    #[cfg(feature = "gssapi-vendored")]
    {
        // NOTE(benesch): linking gssapi_krb5 and its dependencies should one
        // day be the responsibility of a libgssapi-sys project. Unfortunately
        // none of the several options on crates.io are presently up to snuff.
        println!(
            "cargo:rustc-link-search=native={}",
            Path::new(krb5_src::INSTALL_DIR).join("lib").display(),
        );
        println!("cargo:rustc-link-lib=static=gssapi_krb5");
        println!("cargo:rustc-link-lib=static=krb5");
        println!("cargo:rustc-link-lib=static=k5crypto");
        println!("cargo:rustc-link-lib=static=com_err");
        println!("cargo:rustc-link-lib=static=krb5support");
        println!("cargo:rustc-link-lib=resolv")
    }
}

fn find_sasl(metadata: &Metadata) {
    #[cfg(feature = "pkg-config")]
    {
        if let Ok(pkg) = pkg_config::Config::new()
            .print_system_libs(false)
            .env_metadata(true)
            .probe("libsasl2")
        {
            validate_headers(&pkg.include_paths);
            return;
        }
    }

    let (lib_dir, include_dir) = (|| {
        if metadata.host == metadata.target
            && metadata.target.contains("darwin")
            && metadata.want_static != Some(false)
        {
            let lib_dir = PathBuf::from("/usr/lib");
            let include_dir =
                PathBuf::from("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include");
            if lib_dir.join("libsasl2.dylib").exists()
                && include_dir.join("sasl").join("sasl.h").exists()
            {
                return (lib_dir, include_dir);
            }
        }

        for prefix in &[Path::new("/usr"), Path::new("/usr/local")] {
            for lib_dir in vec![
                prefix.join("lib"),
                prefix.join("lib64"),
                prefix.join("lib").join(&metadata.target),
                prefix
                    .join("lib")
                    .join(&metadata.target.replace("unknown-linux-gnu", "linux-gnu")),
            ] {
                let include_dir = prefix.join("include");
                if (lib_dir.join("libsasl2.a").exists()
                    || lib_dir.join("libsasl2.so").exists()
                    || lib_dir.join("libsasl2.dylib").exists())
                    && include_dir.join("sasl").join("sasl.h").exists()
                {
                    return (lib_dir, include_dir);
                }
            }
        }

        panic!(
            "Unable to find libsasl2 on your system. Hints:

  * Have you installed the libsasl2 development package for your platform?
    On Debian-based systems, try libsasl2-dev. On RHEL-based systems, try
    cyrus-sasl-devel.

  * Have you incorrectly set the SASL2_STATIC environment variable when your
    system only supports dynamic linking?

  * Are you willing to enable the `vendored` feature to instead build and link
    against a bundled copy of libsasl2?"
        )
    })();

    validate_headers(&[include_dir]);

    let link_kind = match metadata.want_static {
        Some(true) => "static",
        Some(false) => "dylib",
        None if lib_dir.join("libsasl2.dylib").exists() || lib_dir.join("libsasl2.so").exists() => {
            "dylib"
        }
        None => "static",
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib={}=sasl2", link_kind);
}

fn validate_headers(include_dirs: &[PathBuf]) {
    let mut cc = cc::Build::new();
    for dir in include_dirs {
        cc.include(dir);
    }
    cc.file("version.c");
    let mut lines = cc.expand().lines().collect::<Result<Vec<_>, _>>().unwrap();
    let step: u8 = lines.pop().unwrap().parse().unwrap();
    let minor: u8 = lines.pop().unwrap().parse().unwrap();
    let major: u8 = lines.pop().unwrap().parse().unwrap();
    if major != 2 || minor != 1 || !(26..=27).contains(&step) {
        panic!(
            "system libsasl is v{}.{}.{}, but this version of sasl2-sys \
             requires v2.1.26 or v2.1.27",
            major, minor, step
        );
    }
    // Hack: encode version components as a single byte, so we can decode
    // them at compile-time in Rust.
    print!("cargo:rustc-env=SASL_VERSION_MAJOR=");
    io::stdout().write(&[major, b'\n']).unwrap();
    print!("cargo:rustc-env=SASL_VERSION_MINOR=");
    io::stdout().write(&[minor, b'\n']).unwrap();
    print!("cargo:rustc-env=SASL_VERSION_STEP=");
    io::stdout().write(&[step, b'\n']).unwrap();
}
