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

//! Main SASL API.

use libc::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void, iovec};

use super::prop::propctx;

// Version.

// Hack: decode version components from environment variables, where they
// are encoded as single bytes. `u8::parse` is not yet a `const fn`, but
// indexing into a byte slice is.
const fn decode_version(s: &str) -> u8 {
    s.as_bytes()[0]
}

// Hack: these `const fn`s work around a bug in ctest, which gets confused
// about the `env!` expansion otherwise.

const fn sasl_version_major() -> u8 {
    decode_version(env!("SASL_VERSION_MAJOR"))
}

const fn sasl_version_minor() -> u8 {
    decode_version(env!("SASL_VERSION_MINOR"))
}

const fn sasl_version_step() -> u8 {
    decode_version(env!("SASL_VERSION_STEP"))
}

pub const SASL_VERSION_MAJOR: u8 = sasl_version_major();
pub const SASL_VERSION_MINOR: u8 = sasl_version_minor();
pub const SASL_VERSION_STEP: u8 = sasl_version_step();

pub const SASL_VERSION_FULL: u32 =
    (SASL_VERSION_MAJOR as u32) << 16 | (SASL_VERSION_MINOR as u32) << 8 | SASL_VERSION_STEP as u32;

// Result codes.

pub const SASL_CONTINUE: u32 = 1;
pub const SASL_OK: u32 = 0;
pub const SASL_FAIL: i32 = -1;
pub const SASL_NOMEM: i32 = -2;
pub const SASL_BUFOVER: i32 = -3;
pub const SASL_NOMECH: i32 = -4;
pub const SASL_BADPROT: i32 = -5;
pub const SASL_NOTDONE: i32 = -6;
pub const SASL_BADPARAM: i32 = -7;
pub const SASL_TRYAGAIN: i32 = -8;
pub const SASL_BADMAC: i32 = -9;
pub const SASL_NOTINIT: i32 = -12;

pub const SASL_INTERACT: u32 = 2;
pub const SASL_BADSERV: i32 = -10;
pub const SASL_WRONGMECH: i32 = -11;

pub const SASL_BADAUTH: i32 = -13;
pub const SASL_NOAUTHZ: i32 = -14;
pub const SASL_TOOWEAK: i32 = -15;
pub const SASL_ENCRYPT: i32 = -16;
pub const SASL_TRANS: i32 = -17;

pub const SASL_EXPIRED: i32 = -18;
pub const SASL_DISABLED: i32 = -19;
pub const SASL_NOUSER: i32 = -20;
pub const SASL_BADVERS: i32 = -23;
pub const SASL_UNAVAIL: i32 = -24;
pub const SASL_NOVERIFY: i32 = -26;

pub const SASL_PWLOCK: i32 = -21;
pub const SASL_NOCHANGE: i32 = -22;
pub const SASL_WEAKPASS: i32 = -27;
pub const SASL_NOUSERPASS: i32 = -28;
pub const SASL_NEED_OLD_PASSWD: i32 = -29;
pub const SASL_CONSTRAINT_VIOLAT: i32 = -30;

pub const SASL_BADBINDING: i32 = -32;

pub const SASL_MECHNAMEMAX: u32 = 20;

// Connection state.

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sasl_conn {
    _unused: [u8; 0],
}

pub type sasl_conn_t = sasl_conn;

// Password state.

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sasl_secret {
    pub len: c_ulong,
    pub data: [c_uchar; 1],
}

pub type sasl_secret_t = sasl_secret;

// Random state.

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sasl_rand_s {
    _unused: [u8; 0],
}

pub type sasl_rand_t = sasl_rand_s;

// Memory allocation functions.

pub type sasl_malloc_t = Option<unsafe extern "C" fn(arg1: usize) -> *mut c_void>;
pub type sasl_calloc_t = Option<unsafe extern "C" fn(arg1: usize, arg2: usize) -> *mut c_void>;
pub type sasl_realloc_t =
    Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: usize) -> *mut c_void>;
pub type sasl_free_t = Option<unsafe extern "C" fn(arg1: *mut c_void)>;

extern "C" {
    pub fn sasl_set_alloc(
        arg1: sasl_malloc_t,
        arg2: sasl_calloc_t,
        arg3: sasl_realloc_t,
        arg4: sasl_free_t,
    );
}

// Mutex functions.

pub type sasl_mutex_alloc_t = Option<unsafe extern "C" fn() -> *mut c_void>;
pub type sasl_mutex_lock_t = Option<unsafe extern "C" fn(mutex: *mut c_void) -> c_int>;
pub type sasl_mutex_unlock_t = Option<unsafe extern "C" fn(mutex: *mut c_void) -> c_int>;
pub type sasl_mutex_free_t = Option<unsafe extern "C" fn(mutex: *mut c_void)>;

extern "C" {
    pub fn sasl_set_mutex(
        arg1: sasl_mutex_alloc_t,
        arg2: sasl_mutex_lock_t,
        arg3: sasl_mutex_unlock_t,
        arg4: sasl_mutex_free_t,
    );
}

// Security preference types.

pub type sasl_ssf_t = c_uint;

// Usage flags.

pub const SASL_SUCCESS_DATA: u32 = 4;
pub const SASL_NEED_PROXY: u32 = 8;
pub const SASL_NEED_HTTP: u32 = 16;

// Security property types.

pub const SASL_SEC_NOPLAINTEXT: u32 = 1;
pub const SASL_SEC_NOACTIVE: u32 = 2;
pub const SASL_SEC_NODICTIONARY: u32 = 4;
pub const SASL_SEC_FORWARD_SECRECY: u32 = 8;
pub const SASL_SEC_NOANONYMOUS: u32 = 16;
pub const SASL_SEC_PASS_CREDENTIALS: u32 = 32;
pub const SASL_SEC_MUTUAL_AUTH: u32 = 64;
#[cfg(not(all(target_os = "macos", not(feature = "vendored"))))]
pub const SASL_SEC_MAXIMUM: u32 = 255;
#[cfg(all(target_os = "macos", not(feature = "vendored")))]
pub const SASL_SEC_MAXIMUM: u32 = 65535;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sasl_security_properties {
    pub min_ssf: sasl_ssf_t,
    pub max_ssf: sasl_ssf_t,
    pub maxbufsize: c_uint,
    pub security_flags: c_uint,
    pub property_names: *mut *const c_char,
    pub property_values: *mut *const c_char,
}

pub type sasl_security_properties_t = sasl_security_properties;

// Callbacks.

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sasl_callback {
    pub id: c_ulong,
    pub proc_: Option<unsafe extern "C" fn() -> c_int>,
    pub context: *mut c_void,
}

pub type sasl_callback_t = sasl_callback;

pub const SASL_CB_LIST_END: u32 = 0;

pub type sasl_getopt_t = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        plugin_name: *const c_char,
        option: *const c_char,
        result: *mut *const c_char,
        len: *mut c_uint,
    ) -> c_int,
>;

pub const SASL_CB_GETOPT: u32 = 1;

pub const SASL_LOG_NONE: u32 = 0;
pub const SASL_LOG_ERR: u32 = 1;
pub const SASL_LOG_FAIL: u32 = 2;
pub const SASL_LOG_WARN: u32 = 3;
pub const SASL_LOG_NOTE: u32 = 4;
pub const SASL_LOG_DEBUG: u32 = 5;
pub const SASL_LOG_TRACE: u32 = 6;
pub const SASL_LOG_PASS: u32 = 7;

pub type sasl_log_t = Option<
    unsafe extern "C" fn(context: *mut c_void, level: c_int, message: *const c_char) -> c_int,
>;

pub const SASL_CB_LOG: u32 = 2;

pub type sasl_getpath_t =
    Option<unsafe extern "C" fn(context: *mut c_void, path: *mut *const c_char) -> c_int>;

pub const SASL_CB_GETPATH: u32 = 3;

pub type sasl_verify_type_t = u32;

pub const SASL_VRFY_PLUGIN: sasl_verify_type_t = 0;
pub const SASL_VRFY_CONF: sasl_verify_type_t = 1;
pub const SASL_VRFY_PASSWD: sasl_verify_type_t = 2;
pub const SASL_VRFY_OTHER: sasl_verify_type_t = 3;

pub type sasl_verifyfile_t = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        file: *const c_char,
        type_: sasl_verify_type_t,
    ) -> c_int,
>;

pub const SASL_CB_VERIFYFILE: u32 = 4;

pub type sasl_getconfpath_t =
    Option<unsafe extern "C" fn(context: *mut c_void, path: *mut *mut c_char) -> c_int>;

pub const SASL_CB_GETCONFPATH: u32 = 5;

pub type sasl_getsimple_t = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        id: c_int,
        result: *mut *const c_char,
        len: *mut c_uint,
    ) -> c_int,
>;

pub const SASL_CB_USER: u32 = 16385;
pub const SASL_CB_AUTHNAME: u32 = 16386;
pub const SASL_CB_LANGUAGE: u32 = 16387;
pub const SASL_CB_CNONCE: u32 = 16391;

pub type sasl_getsecret_t = Option<
    unsafe extern "C" fn(
        conn: *mut sasl_conn_t,
        context: *mut c_void,
        id: c_int,
        psecret: *mut *mut sasl_secret_t,
    ) -> c_int,
>;

pub const SASL_CB_PASS: u32 = 16388;

pub type sasl_chalprompt_t = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        id: c_int,
        challenge: *const c_char,
        prompt: *const c_char,
        defresult: *const c_char,
        result: *mut *const c_char,
        len: *mut c_uint,
    ) -> c_int,
>;

pub const SASL_CB_ECHOPROMPT: u32 = 16389;
pub const SASL_CB_NOECHOPROMPT: u32 = 16390;

pub type sasl_getrealm_t = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        id: c_int,
        availrealms: *mut *const c_char,
        result: *mut *const c_char,
    ) -> c_int,
>;

pub const SASL_CB_GETREALM: u32 = 16392;

pub type sasl_authorize_t = Option<
    unsafe extern "C" fn(
        conn: *mut sasl_conn_t,
        context: *mut c_void,
        requested_user: *const c_char,
        rlen: c_uint,
        auth_identity: *const c_char,
        alen: c_uint,
        def_realm: *const c_char,
        urlen: c_uint,
        propctx: *mut propctx,
    ) -> c_int,
>;

pub const SASL_CB_PROXY_POLICY: u32 = 32769;

pub type sasl_server_userdb_checkpass_t = Option<
    unsafe extern "C" fn(
        conn: *mut sasl_conn_t,
        context: *mut c_void,
        user: *const c_char,
        pass: *const c_char,
        passlen: c_uint,
        propctx: *mut propctx,
    ) -> c_int,
>;

pub const SASL_CB_SERVER_USERDB_CHECKPASS: u32 = 32773;

pub type sasl_server_userdb_setpass_t = Option<
    unsafe extern "C" fn(
        conn: *mut sasl_conn_t,
        context: *mut c_void,
        user: *const c_char,
        pass: *const c_char,
        passlen: c_uint,
        propctx: *mut propctx,
        flags: c_uint,
    ) -> c_int,
>;

pub const SASL_CB_SERVER_USERDB_SETPASS: u32 = 32774;

pub const SASL_CU_NONE: u32 = 0;
pub const SASL_CU_AUTHID: u32 = 1;
pub const SASL_CU_AUTHZID: u32 = 2;
pub const SASL_CU_EXTERNALLY_VERIFIED: u32 = 4;
pub const SASL_CU_OVERRIDE: u32 = 8;
pub const SASL_CU_ASIS_MASK: u32 = 65520;
pub const SASL_CU_VERIFY_AGAINST_HASH: u32 = 16;

pub type sasl_canon_user_t = Option<
    unsafe extern "C" fn(
        conn: *mut sasl_conn_t,
        context: *mut c_void,
        in_: *const c_char,
        inlen: c_uint,
        flags: c_uint,
        user_realm: *const c_char,
        out: *mut c_char,
        out_max: c_uint,
        out_len: *mut c_uint,
    ) -> c_int,
>;

pub const SASL_CB_CANON_USER: u32 = 32775;

// Common client/server functions.

pub const SASL_PATH_TYPE_PLUGIN: u32 = 0;
pub const SASL_PATH_TYPE_CONFIG: u32 = 1;

extern "C" {
    pub fn sasl_set_path(path_type: c_int, path: *mut c_char) -> c_int;

    pub fn sasl_version(implementation: *mut *const c_char, version: *mut c_int);

    pub fn sasl_version_info(
        implementation: *mut *const c_char,
        version_string: *mut *const c_char,
        version_major: *mut c_int,
        version_minor: *mut c_int,
        version_step: *mut c_int,
        version_patch: *mut c_int,
    );

    pub fn sasl_done();

    pub fn sasl_server_done() -> c_int;

    pub fn sasl_client_done() -> c_int;

    pub fn sasl_dispose(pconn: *mut *mut sasl_conn_t);

    pub fn sasl_errstring(
        saslerr: c_int,
        langlist: *const c_char,
        outlang: *mut *const c_char,
    ) -> *const c_char;

    pub fn sasl_errdetail(conn: *mut sasl_conn_t) -> *const c_char;

    pub fn sasl_seterror(conn: *mut sasl_conn_t, flags: c_uint, fmt: *const c_char, ...);
}

pub const SASL_NOLOG: u32 = 1;

extern "C" {
    pub fn sasl_getprop(
        conn: *mut sasl_conn_t,
        propnum: c_int,
        pvalue: *mut *const c_void,
    ) -> c_int;
}

pub const SASL_USERNAME: u32 = 0;
pub const SASL_SSF: u32 = 1;
pub const SASL_MAXOUTBUF: u32 = 2;
pub const SASL_DEFUSERREALM: u32 = 3;
pub const SASL_GETOPTCTX: u32 = 4;
pub const SASL_CALLBACK: u32 = 7;
pub const SASL_IPLOCALPORT: u32 = 8;
pub const SASL_IPREMOTEPORT: u32 = 9;
pub const SASL_PLUGERR: u32 = 10;
pub const SASL_DELEGATEDCREDS: u32 = 11;
pub const SASL_SERVICE: u32 = 12;
pub const SASL_SERVERFQDN: u32 = 13;
pub const SASL_AUTHSOURCE: u32 = 14;
pub const SASL_MECHNAME: u32 = 15;
pub const SASL_AUTHUSER: u32 = 16;
pub const SASL_APPNAME: u32 = 17;
pub const SASL_GSS_CREDS: u32 = 18;
pub const SASL_GSS_PEER_NAME: u32 = 19;
pub const SASL_GSS_LOCAL_NAME: u32 = 20;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sasl_channel_binding {
    pub name: *const c_char,
    pub critical: c_int,
    pub len: c_ulong,
    pub data: *const ::std::os::raw::c_uchar,
}
pub type sasl_channel_binding_t = sasl_channel_binding;

pub const SASL_CHANNEL_BINDING: u32 = 21;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sasl_http_request {
    pub method: *const c_char,
    pub uri: *const c_char,
    pub entity: *const ::std::os::raw::c_uchar,
    pub elen: c_ulong,
    pub non_persist: c_uint,
}

pub type sasl_http_request_t = sasl_http_request;

pub const SASL_HTTP_REQUEST: u32 = 22;

extern "C" {
    pub fn sasl_setprop(conn: *mut sasl_conn_t, propnum: c_int, value: *const c_void) -> c_int;
}

pub const SASL_SSF_EXTERNAL: u32 = 100;
pub const SASL_SEC_PROPS: u32 = 101;
pub const SASL_AUTH_EXTERNAL: u32 = 102;

extern "C" {
    pub fn sasl_idle(conn: *mut sasl_conn_t) -> c_int;
}

// Client API.

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sasl_interact {
    pub id: c_ulong,
    pub challenge: *const c_char,
    pub prompt: *const c_char,
    pub defresult: *const c_char,
    pub result: *const c_void,
    pub len: c_uint,
}

pub type sasl_interact_t = sasl_interact;

extern "C" {
    pub fn sasl_client_init(callbacks: *const sasl_callback_t) -> c_int;

    pub fn sasl_client_new(
        service: *const c_char,
        serverFQDN: *const c_char,
        iplocalport: *const c_char,
        ipremoteport: *const c_char,
        prompt_supp: *const sasl_callback_t,
        flags: c_uint,
        pconn: *mut *mut sasl_conn_t,
    ) -> c_int;

    pub fn sasl_client_start(
        conn: *mut sasl_conn_t,
        mechlist: *const c_char,
        prompt_need: *mut *mut sasl_interact_t,
        clientout: *mut *const c_char,
        clientoutlen: *mut c_uint,
        mech: *mut *const c_char,
    ) -> c_int;

    pub fn sasl_client_step(
        conn: *mut sasl_conn_t,
        serverin: *const c_char,
        serverinlen: c_uint,
        prompt_need: *mut *mut sasl_interact_t,
        clientout: *mut *const c_char,
        clientoutlen: *mut c_uint,
    ) -> c_int;
}

// Server API.

extern "C" {
    pub fn sasl_server_init(callbacks: *const sasl_callback_t, appname: *const c_char) -> c_int;

    pub fn sasl_server_new(
        service: *const c_char,
        serverFQDN: *const c_char,
        user_realm: *const c_char,
        iplocalport: *const c_char,
        ipremoteport: *const c_char,
        callbacks: *const sasl_callback_t,
        flags: c_uint,
        pconn: *mut *mut sasl_conn_t,
    ) -> c_int;

    pub fn sasl_global_listmech() -> *mut *const c_char;

    pub fn sasl_listmech(
        conn: *mut sasl_conn_t,
        user: *const c_char,
        prefix: *const c_char,
        sep: *const c_char,
        suffix: *const c_char,
        result: *mut *const c_char,
        plen: *mut c_uint,
        pcount: *mut c_int,
    ) -> c_int;

    pub fn sasl_server_start(
        conn: *mut sasl_conn_t,
        mech: *const c_char,
        clientin: *const c_char,
        clientinlen: c_uint,
        serverout: *mut *const c_char,
        serveroutlen: *mut c_uint,
    ) -> c_int;

    pub fn sasl_server_step(
        conn: *mut sasl_conn_t,
        clientin: *const c_char,
        clientinlen: c_uint,
        serverout: *mut *const c_char,
        serveroutlen: *mut c_uint,
    ) -> c_int;

    pub fn sasl_checkapop(
        conn: *mut sasl_conn_t,
        challenge: *const c_char,
        challen: c_uint,
        response: *const c_char,
        resplen: c_uint,
    ) -> c_int;

    pub fn sasl_checkpass(
        conn: *mut sasl_conn_t,
        user: *const c_char,
        userlen: c_uint,
        pass: *const c_char,
        passlen: c_uint,
    ) -> c_int;

    pub fn sasl_user_exists(
        conn: *mut sasl_conn_t,
        service: *const c_char,
        user_realm: *const c_char,
        user: *const c_char,
    ) -> c_int;

    pub fn sasl_setpass(
        conn: *mut sasl_conn_t,
        user: *const c_char,
        pass: *const c_char,
        passlen: c_uint,
        oldpass: *const c_char,
        oldpasslen: c_uint,
        flags: c_uint,
    ) -> c_int;
}

pub const SASL_SET_CREATE: u32 = 1;
pub const SASL_SET_DISABLE: u32 = 2;
pub const SASL_SET_NOPLAIN: u32 = 4;
pub const SASL_SET_CURMECH_ONLY: u32 = 8;

// Auxilary property support.

// TODO(benesch): these cause ctest to panic.
// pub const SASL_AUX_ALL: &'static [u8; 2] = b"*\0";
// pub const SASL_AUX_PASSWORD_PROP: &'static [u8; 13] = b"userPassword\0";
// pub const SASL_AUX_PASSWORD: &'static [u8; 14] = b"*userPassword\0";
// pub const SASL_AUX_UIDNUM: &'static [u8; 10] = b"uidNumber\0";
// pub const SASL_AUX_GIDNUM: &'static [u8; 10] = b"gidNumber\0";
// pub const SASL_AUX_FULLNAME: &'static [u8; 6] = b"gecos\0";
// pub const SASL_AUX_HOMEDIR: &'static [u8; 14] = b"homeDirectory\0";
// pub const SASL_AUX_SHELL: &'static [u8; 11] = b"loginShell\0";
// pub const SASL_AUX_MAILADDR: &'static [u8; 5] = b"mail\0";
// pub const SASL_AUX_UNIXMBX: &'static [u8; 17] = b"mailMessageStore\0";
// pub const SASL_AUX_MAILCHAN: &'static [u8; 22] = b"mailSMTPSubmitChannel\0";

extern "C" {
    pub fn sasl_auxprop_request(conn: *mut sasl_conn_t, propnames: *mut *const c_char) -> c_int;

    pub fn sasl_auxprop_getctx(conn: *mut sasl_conn_t) -> *mut propctx;

    pub fn sasl_auxprop_store(
        conn: *mut sasl_conn_t,
        ctx: *mut propctx,
        user: *const c_char,
    ) -> c_int;
}

// Security layer.

extern "C" {
    pub fn sasl_encode(
        conn: *mut sasl_conn_t,
        input: *const c_char,
        inputlen: c_uint,
        output: *mut *const c_char,
        outputlen: *mut c_uint,
    ) -> c_int;

    pub fn sasl_encodev(
        conn: *mut sasl_conn_t,
        invec: *const iovec,
        numiov: c_uint,
        output: *mut *const c_char,
        outputlen: *mut c_uint,
    ) -> c_int;

    pub fn sasl_decode(
        conn: *mut sasl_conn_t,
        input: *const c_char,
        inputlen: c_uint,
        output: *mut *const c_char,
        outputlen: *mut c_uint,
    ) -> c_int;
}
