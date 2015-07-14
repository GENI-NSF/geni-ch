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
pkgsysconfdir = $(sysconfdir)/$(PACKAGE)

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
	-e 's|@pkgsysconfdir[@]|$(pkgsysconfdir)|g' \
	-e 's|@prefix[@]|$(prefix)|g' \
	-e 's|@tooldir[@]|$(tooldir)|g' \
	-e 's|@gcfdir[@]|$(gcfdir)|g'

geni-check-errors geni-list-idp-members geni-list-pending-requests geni-sign-tool-csr geni-expiring-certs: Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

geni-check-errors: $(srcdir)/geni-check-errors.in
geni-list-idp-members: $(srcdir)/geni-list-idp-members.in
geni-list-pending-requests: $(srcdir)/geni-list-pending-requests.in
geni-sign-tool-csr: $(srcdir)/geni-sign-tool-csr.in
geni-expiring-certs: $(srcdir)/geni-expiring-certs.in

# Distribute but do not install
EXTRA_DIST =  \
	geni-check-errors.in \
	geni-list-idp-members.in \
	geni-list-pending-requests.in \
	geni-sign-tool-csr.in \
	geni-expiring-certs.in

CLEANFILES =  \
	geni-check-errors \
	geni-list-idp-members \
	geni-list-pending-requests \
	geni-sign-tool-csr \
	geni-expiring-certs

sbin_SCRIPTS = \
	geni-check-errors \
	geni-list-idp-members \
	geni-list-pending-requests \
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
                geni-remove-project-member \
                gmoc_list_contacts \
                gmoc_list_slices \
                report_genich_relations

dist_sbin_SCRIPTS = \
	geni-add-member-privilege \
	geni-create-ma-crl \
	geni-list-member-projects \
	geni-list-pending-requests \
	geni-revoke-member-certificate \
	geni-revoke-member-privilege

if INSTALL_GITHASH
dist_pkgsysconf_DATA = geni-ch-githash
endif


# GPO Lab
# Install in /usr/local/lib, not /usr/lib
localpythondir = $(subst /usr/lib,/usr/local/lib,$(pythondir))
if GPO_LAB
  nobase_dist_localpython_DATA = chapiclient/__init__.py chapiclient/chapi.py
else
  nobase_dist_python_DATA = chapiclient/__init__.py chapiclient/chapi.py
endif
