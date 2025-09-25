#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(connectdump, 1.0.0, minfrin@sharp.fm)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_FILES([Makefile connectdump.spec])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

AC_SUBST([libexecdir], [$libexecdir])

# Checks for libraries.
PKG_CHECK_MODULES(apr, apr-1 >= 1.3)
PKG_CHECK_MODULES(apu, apr-util-1 >= 1.3)
PKG_CHECK_MODULES(pcap, libpcap >= 1)

CFLAGS="$CFLAGS $apr_CFLAGS $apu_CFLAGS $pcap_CFLAGS $libselinux_CFLAGS $dbus_CFLAGS $icu_CFLAGS"
CPPFLAGS="$CPPFLAGS $apr_CPPFLAGS $apu_CPPFLAGS $pcap_CPPFLAGS $libselinux_CPPFLAGS $dbus_CPPFLAGS $icu_CPPFLAGS"
LDFLAGS="$LDFLAGS $apr_LDFLAGS $apu_LDFLAGS $pcap_LDFLAGS $libselinux_LDFLAGS $dbus_LDFLAGS $icu_LDFLAGS"
LIBS="$LIBS $apr_LIBS $apu_LIBS $libedit_LIBS $pcap_LIBS $dbus_LIBS $icu_LIBS"

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

# Checks for headers
AC_CHECK_HEADERS([pcap/pcap.h])

# Checks for library functions.
AC_FUNC_MALLOC

AC_OUTPUT

