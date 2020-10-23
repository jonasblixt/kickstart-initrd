dnl Kickstart-initrd

AC_PREREQ(2.59)
AC_INIT([kickstart-initrd], [0.2.0], [Jonas Blixt, <jonpe960@gmail.com>])

m4_pattern_forbid([^AX_(CHECK_ENABLE_DEBUG|CODE_COVERAGE|COMPILER_FLAGS|COMPILER_FLAGS_(CFLAGS|CXXFLAGS|LDFLAGS))\b],
  [Unexpanded AX_ macro found. Please install GNU autoconf-archive])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])

AM_PROG_AR
LT_INIT
AC_PROG_CC

dnl this allows us specify individual liking flags for each target
AM_PROG_CC_C_O

dnl Initialize Libtool

dnl Check if Libtool is present
dnl Libtool is used for building share libraries
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(BPAK, [bpak >= 0.4.0])
AC_SUBST(BPAK_CFLAGS)
AC_SUBST(BPAK_LIBS)

AC_CHECK_TOOL([BPAK_TOOL], [bpak])

if test x"$BPAK_TOOL" = x; then
    AC_MSG_ERROR([bpak tools not found])
fi

AC_ARG_VAR([KEYSTORE_FILE], BPAK keystore file)

if test x"$KEYSTORE_FILE" = x; then
    AC_MSG_ERROR([A keystore file must be specified])
fi

AC_MSG_NOTICE([Using Keystore: $KEYSTORE_FILE])
AC_MSG_NOTICE([Using bpak tool: $BPAK_TOOL])

AC_CONFIG_COMMANDS([src/keystore.c],
  [$BPAK_TOOL generate keystore $KEYSTORE_FILE --name ks-internal > src/keystore.c],
  [BPAK_TOOL=$BPAK_TOOL
  KEYSTORE_FILE=$KEYSTORE_FILE])

AC_CONFIG_FILES([Makefile
                src/Makefile
                test/Makefile])
AX_CODE_COVERAGE

dnl Dependencies build
dnl AC_CONFIG_SUBDIRS([deps/dep1])

AC_OUTPUT
