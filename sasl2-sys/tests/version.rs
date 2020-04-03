use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

use libc::c_int;

#[test]
fn test_version() {
    let mut implementation: *const c_char = ptr::null();
    let mut version_string: *const c_char = ptr::null();
    let mut version_major: c_int = 0;
    let mut version_minor: c_int = 0;
    let mut version_step: c_int = 0;
    let mut version_patch: c_int = 0;
    unsafe {
        sasl2_sys::sasl::sasl_version_info(
            &mut implementation,
            &mut version_string,
            &mut version_major,
            &mut version_minor,
            &mut version_step,
            &mut version_patch,
        );
        println!(
            "implementation={:?} version_string={:?} version={}.{}.{}-{}",
            CStr::from_ptr(implementation),
            CStr::from_ptr(version_string),
            version_major,
            version_minor,
            version_step,
            version_patch
        );
    }
}

#[test]
fn test_readme_deps() {
    version_sync::assert_markdown_deps_updated!("../README.md");
}

#[test]
fn test_html_root_url() {
    version_sync::assert_html_root_url_updated!("src/lib.rs");
}
