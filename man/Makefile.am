pkgsysconfdir = $(sysconfdir)/$(PACKAGE)

edit = sed \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
	-e 's|@pkgsysconfdir[@]|$(pkgsysconfdir)|g'

TEMPLATES = \
	geni-check-errors.1 \
	geni-maintenance.1

TEMPLATES.IN = $(TEMPLATES:%=%.in)

$(TEMPLATES): Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

%: $(srcdir)/%.in

# Distribute but do not install
EXTRA_DIST = $(TEMPLATES.IN)

CLEANFILES = $(TEMPLATES)

man_MANS = \
	geni-check-errors.1 \
	geni-maintenance.1

dist_man_MANS = \
	geni-add-member-privilege.1 \
	geni-assert-email.1 \
	geni-delete-outside-cert.1 \
	geni-expiring-certs.1 \
	geni-install-templates.1 \
	geni-list-idp-members.1 \
	geni-list-member-projects.1 \
	geni-list-pending-requests.1 \
	geni-revoke-member-certificate.1 \
	geni-revoke-member-privilege.1 \
	geni-sign-tool-csr.1
