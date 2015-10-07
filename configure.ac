AC_INIT([geni-chapi], [2.5], [portal-help@geni.net])
AM_INIT_AUTOMAKE([foreign -Wall -Wno-portability])
AC_PROG_MKDIR_P
AC_PROG_INSTALL
AC_PROG_LN_S
AM_PATH_PYTHON([2.6])

gpolab=yes
AM_CONDITIONAL(GPO_LAB, [test x"$gpo_lab" = xyes])

AC_ARG_ENABLE([gpo_lab],
[  --enable-gpo-lab    Turn on GPO Lab modifications],
[case "${enableval}" in
  yes) gpo_lab=true ;;
  no)  gpo_lab=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-gpo-lab]) ;;
esac],[gpo_lab=false])
AM_CONDITIONAL([GPO_LAB], [test x$gpo_lab = xtrue])

AM_CONDITIONAL(INSTALL_GITHASH, [test -f etc/geni-chapi-githash])

AC_CONFIG_FILES([Makefile plugins/Makefile tools/Makefile etc/Makefile])
AC_CONFIG_FILES([bin/Makefile man/Makefile data/Makefile db/Makefile])
AC_CONFIG_FILES([templates/Makefile])
AC_OUTPUT
