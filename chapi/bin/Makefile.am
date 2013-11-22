edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
	-e 's|@pkgsysconfdir[@]|$(pkgsysconfdir)|g' \
	-e 's|@prefix[@]|$(prefix)|g'

geni-check-errors: Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

geni-check-errors: $(srcdir)/geni-check-errors.in

dist_pkgdata_DATA = \
	amsoil-log-out.txt \
	apache-error-log-out.txt \
	ch-error-log-out.txt \
	chapi-log-out.txt

dist_sbin_SCRIPTS = geni-check-errors
