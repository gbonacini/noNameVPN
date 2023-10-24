#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([tvpv],[m4_esyscmd( tr -d '\n' < version )])

LUA_VERSION="5.4"
CXXFLAGS=""
LDFLAGS=""

AC_CONFIG_SRCDIR([src/nnvpn.cpp])

AC_CONFIG_HEADERS([include/config.h])

LT_INIT
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE([disable])

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_FILES([Makefile
		src/Makefile])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL

# Checks for header files.
m4_warn([obsolete],
[The preprocessor macro `STDC_HEADERS' is obsolete.
  Except in unusual embedded environments, you can safely include all
  ISO C90 headers unconditionally.])dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# LUA
# AX_PROG_LUA([5.2], [5.4])
AX_LUA_LIBS
AX_LUA_HEADERS

AC_CANONICAL_HOST
case $host_os in
  darwin* )
              OPTIMIZATION=-O3
              if test "x$_DEBUG_MEM_" = xyes; then
                        OPTIMIZATION=-O0
              fi
              if test "x$CC" = xgcc; then
                    CPPFLAGS=" -g -Wextra -Wall -std=c++20 -Wno-deprecated-declarations \
                             -D_FORTIFY_SOURCE=2 ${OPTIMIZATION} -fstack-protector \
                             -I/usr/local/ssl/include/ \
                             --param=ssp-buffer-size=4 -Wformat -Werror=format-security ${INC_SSL_CUSTOM}"
                    LDFLAGS="-lresolv ${LIB_SSL_CUSTOM}"
              else
                    CPPFLAGS=" ${OPTIMIZATION} -g -Wall "
              fi

        ;;
  linux*)
              OPTIMIZATION=-O3
              if test "x$_DEBUG_MEM" = xyes; then
                        OPTIMIZATION=-O0
              fi
              if test "x$CC" = xgcc; then
                    CPPFLAGS=" -ggdb -Wextra -Wall -D_XOPEN_SOURCE -std=c++20 \
                             -D_FORTIFY_SOURCE=2 ${OPTIMIZATION} -fstack-protector \
                             --param=ssp-buffer-size=4 -Wformat -Werror=format-security ${INC_SSL_CUSTOM}"
                    LDFLAGS="$LDFLAGS -Wl,-z,relro -lresolv ${LIB_SSL_CUSTOM}"
              else
                    CPPFLAGS=" ${OPTIMIZATION} -g -Wall -std=c++20 -D_XOPEN_SOURCE "
              fi
        ;;
    *)
            OPTIMIZATION=-O3
            CPPFLAGS=" ${OPTIMIZATION} -g -Wall "
            LDFLAGS="-lresolv  ${LIB_SSL_CUSTOM}"
            #AC_MSG_ERROR([Your platform is not currently supported])
        ;;
esac

# Libs list autmatically generated from dependecy script
AC_CHECK_LIB([cap],[cap_get_proc],[],[AC_MSG_FAILURE([could not find lib capability])])
AC_CHECK_LIB([crypto],[EVP_KDF_up_ref],[],[AC_MSG_FAILURE([could not find lib crypto])])
AC_CHECK_LIB([ssl],[RSA_set0_key],[],[AC_MSG_FAILURE([could not find lib ssl])])

AC_OUTPUT
