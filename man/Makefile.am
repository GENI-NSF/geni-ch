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

# Distribute but do not install
EXTRA_DIST = \
	geni-check-errors.1.in

CLEANFILES = \
	geni-check-errors.1

man_MANS = \
	geni-check-errors.1

dist_man_MANS = \
	geni-add-member-privilege.1 \
	geni-archive-data-tables.1 \
	geni-expiring-certs.1 \
	geni-list-idp-members.1 \
	geni-list-member-projects.1 \
	geni-list-pending-requests.1 \
	geni-revoke-member-privilege.1 \
	geni-sign-tool-csr.1
