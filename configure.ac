AC_INIT([[idas2etracer]],[[0.1]],[lucab@debian.org])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_LANG([C++])
CXXFLAGS="-m32 $CXXFLAGS"
AC_PROG_CXX
AC_PROG_LN_S
AC_DISABLE_STATIC
LT_INIT

AC_ARG_WITH(idasdk,
  AS_HELP_STRING([--with-idasdk=path],
    [Location of IDA SDK headers]),
  [
  if test -d $with_idasdk
  then
    idasdk_path=$with_idasdk
    AC_MSG_RESULT([Using IDA SDK in path $with_idasdk])
  else
    AC_MSG_ERROR([Invalid IDA SDK path])
  fi
  ], idasdk_path="")

AS_IF([test -n $idasdk_path], [
  CXXFLAGS="$CXXFLAGS -I$idasdk_path"
])

AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_FILES([Makefile src/Makefile s2e/Makefile])

AC_OUTPUT

