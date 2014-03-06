#----------------------------------------------------------------------
# 'tooldir' and 'gcfdir' are here for substitution into scripts.
#
# TODO: keep 'tooldir' in sync with ../tools/Makefile.am (see note
#       there)
#
# TODO: add gcfdir to configure so it can be specified for all of
#       chapi in one place, and even hunted for in known locations.
#----------------------------------------------------------------------
tooldir = $(pkgdatadir)/../geni-ch/chapi/chapi/tools
gcfdir = $(pkgdatadir)/../geni-ch/gcf/src

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
	-e 's|@pkgsysconfdir[@]|$(pkgsysconfdir)|g' \
	-e 's|@prefix[@]|$(prefix)|g' \
	-e 's|@tooldir[@]|$(tooldir)|g' \
	-e 's|@gcfdir[@]|$(gcfdir)|g'

geni-check-errors geni-sign-tool-csr: Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

geni-check-errors: $(srcdir)/geni-check-errors.in
geni-sign-tool-csr: $(srcdir)/geni-sign-tool-csr.in

dist_pkgdata_DATA = \
	amsoil-log-out.txt \
	apache-error-log-out.txt \
	ch-error-log-out.txt \
	chapi-log-out.txt

dist_sbin_SCRIPTS = geni-check-errors geni-sign-tool-csr
