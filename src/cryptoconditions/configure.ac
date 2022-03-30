#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_HEADERS([src/cryptoconditions-config.h])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SUBDIRS([src/include/secp256k1])

AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_INIT

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC

# Checks for libraries.

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([arpa/inet.h float.h inttypes.h limits.h locale.h malloc.h netinet/in.h stddef.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

AC_MSG_CHECKING([for strlcpy])
AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <string.h>]],[[
               char a[2];
               if (strlcpy(a, "yes", 2) != 3)
                   return 1;]])],
              [
               AC_MSG_RESULT([yes])
               AC_DEFINE_UNQUOTED([HAVE_STRLCPY], 1,
                                  [Define to 1 if you have the strlcpy function.])
              ],
              [
               AC_MSG_RESULT([no])
               AC_DEFINE_UNQUOTED([HAVE_STRLCPY], 0,
                                  [Define to 1 if you have the strlcpy function.])
              ])

AC_MSG_CHECKING([for strlcat])
AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <string.h>]],[[
               char a[4] = "no";
               if (strlcat(a, "yes", 4) != 5)
                   return 1;]])],
              [
               AC_MSG_RESULT([yes])
               AC_DEFINE_UNQUOTED([HAVE_STRLCAT], 1,
                                  [Define to 1 if you have the strlcat function.])
              ],
              [
               AC_MSG_RESULT([no])
               AC_DEFINE_UNQUOTED([HAVE_STRLCAT], 0,
                                  [Define to 1 if you have the strlcat function.])
              ])

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([localeconv memchr memset])

# set linux or macos build env
build_linux=no
build_mac=no
case $host in
    *linux*)
        build_linux=yes
        ;;
    *darwin*)
        build_mac=yes
        ;;
    *)
        AC_MSG_ERROR(["OS $host_os is not supported for build"])
        ;;
esac
AM_CONDITIONAL([BUILD_LINUX], [test x$build_linux = xyes])
AM_CONDITIONAL([BUILD_DARWIN], [test x$build_mac = xyes])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "  host           = $host"


