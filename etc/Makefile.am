pkgsysconfdir = $(sysconfdir)/$(PACKAGE)

edit = sed -e 's|@VERSION[@]|$(VERSION)|g'

TEMPLATES = geni-ch-version.txt

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

dist_pkgsysconf_DATA = \
	example-chapi.ini \
	example-parameters.json \
	geni-ch-version.txt \
	logging_config.conf \
	credential_store_policy.json \
	logging_policy.json \
	member_authority_policy.json \
	slice_authority_policy.json

if INSTALL_GITHASH
pkgsysconf_DATA = geni-chapi-githash
endif
