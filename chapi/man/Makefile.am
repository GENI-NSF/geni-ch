edit = sed \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g'

geni-check-errors.1: Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

geni-check-errors.1: $(srcdir)/geni-check-errors.1.in

dist_man_MANS = \
	geni-check-errors.1 \
	geni-expiring-certs.1 \
	geni-list-member-projects.1 \
	geni-sign-tool-csr.1
