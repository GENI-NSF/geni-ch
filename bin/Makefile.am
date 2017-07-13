#----------------------------------------------------------------------
# 'chapidir' and 'gcfdir' are here for substitution into scripts.
#
# TODO: keep 'chapidir' in sync with variables in ../tools/Makefile.am
#       and ../plugins/Makefile.am (see notes there)
#
# TODO: add gcfdir to configure so it can be specified for all of
#       chapi in one place, and even hunted for in known locations.
#----------------------------------------------------------------------
chapidir = $(pkgdatadir)/../geni-ch/chapi/chapi
gcfdir = $(pkgdatadir)/../geni-ch/gcf/src
pkgsysconfdir = $(sysconfdir)/$(PACKAGE)
templatesdir = $(pkgdatadir)/templates

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
	-e 's|@pkgsysconfdir[@]|$(pkgsysconfdir)|g' \
	-e 's|@prefix[@]|$(prefix)|g' \
	-e 's|@chapidir[@]|$(chapidir)|g' \
	-e 's|@gcfdir[@]|$(gcfdir)|g' \
	-e 's|@templatesdir[@]|$(templatesdir)|g'

TEMPLATES = \
	geni-check-errors \
	geni-install-templates \
	geni-list-idp-members \
	geni-list-pending-requests \
	geni-maintenance \
	geni-sign-tool-csr \
	geni-expiring-certs

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

sbin_SCRIPTS = \
	geni-check-errors \
	geni-install-templates \
	geni-list-idp-members \
	geni-list-pending-requests \
	geni-maintenance \
	geni-sign-tool-csr \
	geni-expiring-certs

dist_pkgdata_DATA = \
	amsoil-log-out.txt \
	apache-error-log-out.txt \
	ch-error-log-out.txt \
	chapi-log-out.txt

dist_bin_SCRIPTS = \
	geni-add-member-attribute \
	geni-add-project-member \
	geni-add-trusted-tool \
	geni-assert-email \
	geni-delete-outside-cert \
	geni-disable-user \
	geni-enable-user \
	geni-ops-report \
	geni-remove-member-attribute \
	geni-remove-project-member

dist_sbin_SCRIPTS = \
	geni-add-member-privilege \
	geni-create-ma-crl \
	geni-init-ca \
	geni-init-services \
	geni-list-member-projects \
	geni-list-pending-requests \
	geni-revoke-member-certificate \
	geni-revoke-member-privilege

# GPO Lab
# Install in /usr/local/lib, not /usr/lib
localpythondir = $(subst /usr/lib,/usr/local/lib,$(pythondir))
if GPO_LAB
  nobase_dist_localpython_DATA = chapiclient/__init__.py chapiclient/chapi.py
else
  nobase_dist_python_DATA = chapiclient/__init__.py chapiclient/chapi.py
endif
