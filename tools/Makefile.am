# TODO: change this to a more sane directory like
#       $(pkgdatadir)/tools where $pkgdatadir is
#       /usr/share/geni-chapi or similar
tooldir = $(pkgdatadir)/../geni-ch/chapi/chapi/tools

pkgsysconfdir = $(sysconfdir)/$(PACKAGE)

edit = sed -e 's|@pkgsysconfdir[@]|$(pkgsysconfdir)|g'

TEMPLATES = chapi_utils.py

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

dist_tool_DATA = \
	ABACManager.py \
	ABACKeyId.py \
	CH_constants.py \
	MA_constants.py \
	SA_constants.py \
	SpeaksFor.py \
	__init__.py \
	cert_utils.py \
	ch_server.py \
	ch_server.wsgi \
	chapi_log.py \
	chapi_utils.py \
	client.py \
	credential_tools.py \
	cs_utils.py \
	dbtest.py \
	dbutils.py \
	file_checker.py \
	geni_constants.py \
	geni_utils.py \
	guard_utils.py \
	mapped_tables.py \
	manage_service_attributes.py \
	multiclient.py \
	pluginmanager.py \
	policy_file_checker.py \
	portal_client.py \
	test_server.py
