#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")"

if [[ $# -ne 1 ]]; then
    echo "fatal: usage: $0 VERSION" >&2
    exit 1
fi

version=$1

set -x
for ext in tar.gz tar.gz.sig; do
    curl -fsSL "https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-$version/cyrus-sasl-$version.$ext" > "sasl2.$ext"
done

gpg --verify sasl2.tar.gz.sig sasl2.tar.gz

rm -rf sasl2
mkdir -p sasl2
tar --strip-components=1 -C sasl2 -xf sasl2.tar.gz
rm sasl2.tar.gz sasl2.tar.gz.sig

find sasl2 -name .gitignore -delete

patch -sp1 <<'EOF'
--- a/sasl2/configure.ac
+++ b/sasl2/configure.ac
@@ -69,6 +69,8 @@ AC_CANONICAL_TARGET

 AM_INIT_AUTOMAKE([1.11 tar-ustar dist-bzip2 foreign -Wno-portability subdir-objects])

+AM_MAINTAINER_MODE
+
 DIRS=""

 AC_ARG_ENABLE(cmulocal,
EOF

# TODO(benesch): why did upstream remove this necessary patch? There is no
# justification provided in either the issue or the commit log.
patch -Rsp1 <<'EOF'
From 8c6ae2ccdfad00407c0e3036c97df31937b49049 Mon Sep 17 00:00:00 2001
From: Quanah Gibson-Mount <quanah@symas.com>
Date: Fri, 14 Jul 2017 11:34:17 -0700
Subject: [PATCH] Fixes https://github.com/cyrusimap/cyrus-sasl/issues/440

---
 sasl2/m4/sasl2.m4 | 9 +++------
 1 file changed, 3 insertions(+), 6 deletions(-)

diff --git a/sasl2/m4/sasl2.m4 b/sasl2/m4/sasl2.m4
index 17df383b..537e2837 100644
--- a/sasl2/m4/sasl2.m4
+++ b/sasl2/m4/sasl2.m4
@@ -112,12 +112,9 @@ if test "$gssapi" != no; then
   fi

   if test "$gss_impl" = "auto" -o "$gss_impl" = "mit"; then
-    # check for libkrb5support first
-    AC_CHECK_LIB(krb5support,krb5int_getspecific,K5SUP=-lkrb5support K5SUPSTATIC=$gssapi_dir/libkrb5support.a,,${LIB_SOCKET})
-
     gss_failed=0
     AC_CHECK_LIB(gssapi_krb5,gss_unwrap,gss_impl="mit",gss_failed=1,
-                 ${GSSAPIBASE_LIBS} -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err ${K5SUP} -lresolv -ldl ${LIB_SOCKET})
+                 ${GSSAPIBASE_LIBS} -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err ${LIB_SOCKET})
     if test "$gss_impl" != "auto" -a "$gss_failed" = "1"; then
       gss_impl="failed"
     fi
@@ -169,8 +166,8 @@ if test "$gssapi" != no; then
   fi

   if test "$gss_impl" = "mit"; then
-    GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err ${K5SUP}"
-    GSSAPIBASE_STATIC_LIBS="$GSSAPIBASE_LIBS $gssapi_dir/libgssapi_krb5.a $gssapi_dir/libkrb5.a $gssapi_dir/libk5crypto.a $gssapi_dir/libcom_err.a ${K5SUPSTATIC}"
+    GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err"
+    GSSAPIBASE_STATIC_LIBS="$GSSAPIBASE_LIBS $gssapi_dir/libgssapi_krb5.a $gssapi_dir/libkrb5.a $gssapi_dir/libk5crypto.a $gssapi_dir/libcom_err.a"
   elif test "$gss_impl" = "heimdal"; then
     CPPFLAGS="$CPPFLAGS"
     GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi -lkrb5 -lasn1 -lroken ${LIB_CRYPT} ${LIB_DES} -lcom_err"
EOF

# Upstream incorrectly uses `ifdef PIC` to mean "building a shared library"
# and the inverse to mean "building a static library." Rust requires that
# we build static libraries with PIC, so we go fix up all these ifdefs
# appropriately.
patch -sp1 << 'EOF'
diff --git a/sasl2/lib/dlopen.c b/sasl2/lib/dlopen.c
index 8284cd8..cea0387 100644
--- a/sasl2/lib/dlopen.c
+++ b/sasl2/lib/dlopen.c
@@ -56,10 +56,8 @@
 #include <sasl.h>
 #include "saslint.h"

-#ifndef PIC
 #include <saslplug.h>
 #include "staticopen.h"
-#endif

 #ifdef DO_DLOPEN
 #if HAVE_DIRENT_H
@@ -414,11 +412,9 @@ int _sasl_load_plugins(const add_plugin_list_t *entrypoints,
     DIR *dp;
     struct dirent *dir;
 #endif
-#ifndef PIC
     add_plugin_t *add_plugin;
     _sasl_plug_type type;
     _sasl_plug_rec *p;
-#endif

     if (! entrypoints
 	|| ! getpath_cb
@@ -429,7 +425,6 @@ int _sasl_load_plugins(const add_plugin_list_t *entrypoints,
 	|| ! verifyfile_cb->proc)
 	return SASL_BADPARAM;

-#ifndef PIC
     /* do all the static plugins first */

     for(cur_ep = entrypoints; cur_ep->entryname; cur_ep++) {
@@ -456,15 +451,8 @@ int _sasl_load_plugins(const add_plugin_list_t *entrypoints,
 	    	result = add_plugin(p->name, p->plug);
 	}
     }
-#endif /* !PIC */

-/* only do the following if:
- * 
- * we support dlopen()
- *  AND we are not staticly compiled
- *      OR we are staticly compiled and TRY_DLOPEN_WHEN_STATIC is defined
- */
-#if defined(DO_DLOPEN) && (defined(PIC) || (!defined(PIC) && defined(TRY_DLOPEN_WHEN_STATIC)))
+#if defined(TRY_DLOPEN_WHEN_STATIC)
     /* get the path to the plugins */
     result = ((sasl_getpath_t *)(getpath_cb->proc))(getpath_cb->context,
 						    &path);
@@ -545,7 +533,7 @@ int _sasl_load_plugins(const add_plugin_list_t *entrypoints,
 	}

     } while ((c!='=') && (c!=0));
-#endif /* defined(DO_DLOPEN) && (!defined(PIC) || (defined(PIC) && defined(TRY_DLOPEN_WHEN_STATIC))) */
+#endif

     return SASL_OK;
 }
diff --git a/sasl2/lib/server.c b/sasl2/lib/server.c
index 8d4c322..7cbd1cb 100644
--- a/sasl2/lib/server.c
+++ b/sasl2/lib/server.c
@@ -823,7 +823,7 @@ int sasl_server_init(const sasl_callback_t *callbacks,
     int ret;
     const sasl_callback_t *vf;
     const char *pluginfile = NULL;
-#ifdef PIC
+#if false
     sasl_getopt_t *getopt;
     void *context;
 #endif
@@ -894,7 +894,7 @@ int sasl_server_init(const sasl_callback_t *callbacks,
     /* load internal plugins */
     sasl_server_add_plugin("EXTERNAL", &external_server_plug_init);

-#ifdef PIC
+#if false
     /* delayed loading of plugins? (DSO only, as it doesn't
      * make much [any] sense to delay in the static library case) */
     if (_sasl_getcallback(NULL, SASL_CB_GETOPT, (sasl_callback_ft *)&getopt, &context)
EOF

(cd sasl2 && autoreconf -iv && rm -rf autom4te.cache)
