#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([Async ONC/RPC Library], [0.5], [csabol@gmail.com], [libarpc])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([libarpc/auth_des.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE(gss,[   --enable-gss          Turn on gss api],
	[case "${enableval}" in
	  yes) gss=true ; AC_CHECK_LIB([gssapi],[gss_init_sec_context]) ;;
	  no) gss=false ;;
	  *) AC_MSG_ERROR(bad value ${enableval} for --enable-gss) ;;
	 esac],[gss=false])
AM_CONDITIONAL(GSS, test x$gss = xtrue)
if test x$gss = xtrue; then
	AC_DEFINE(HAVE_LIBGSSAPI, 1, [])
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_PROG_RANLIB

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lutil':
#AC_CHECK_LIB([util], [main])
AC_CHECK_LIB([wrap], [hosts_access])
AC_CHECK_LIB([event], [event_new])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h sys/stat.h sys/time.h syslog.h unistd.h time.h ifaddrs.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_GETGROUPS
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_FUNC_WAIT3
AC_CHECK_FUNCS([strlcpy strlcat alarm bzero clock_gettime dup2 endgrent gethostbyname gethostname gettimeofday inet_ntoa memmove memset socket strcasecmp strchr strdup strerror strpbrk strrchr strtol uname])

[
#include <sys/types.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
]

# Check for declarations
AC_CHECK_DECLS([clock_gettime, clockid_t])

# Checks for structure variants
AC_CHECK_MEMBERS([struct sockaddr_storage.ss_len,
		  struct sockaddr.sa_len], [], [],
[
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
])

AC_CONFIG_FILES([Makefile 
		 libarpc/Makefile
		 arpcbind/Makefile
		 arpcgen/Makefile
		 arpcinfo/Makefile
		 test/Makefile])
AC_OUTPUT
