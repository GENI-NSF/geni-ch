pkgsysconfdir = $(sysconfdir)/$(PACKAGE)

# TODO: change this to a more sane directory like
#       $(pkgdatadir)/plugins where $pkgdatadir is
#       /usr/share/geni-chapi or similar
plugindir = $(pkgdatadir)/../geni-ch/chapi/chapi/plugins

edit = sed \
	-e 's|@bindir[@]|$(bindir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
	-e 's|@pkgsysconfdir[@]|$(pkgsysconfdir)|g' \
	-e 's|@prefix[@]|$(prefix)|g'

chapiv1rpc/chapi/Parameters.py: Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

chapiv1rpc/chapi/Parameters.py: $(srcdir)/chapiv1rpc/chapi/Parameters.py.in

# Distribute but do not install
EXTRA_DIST =  \
	chapiv1rpc/chapi/Parameters.py.in

CLEANFILES =  \
	chapiv1rpc/chapi/Parameters.py

nobase_plugin_DATA = \
	chapiv1rpc/chapi/Parameters.py

nobase_dist_plugin_DATA = \
	chapiv1rpc/MANIFEST.json \
	chapiv1rpc/__init__.py \
	chapiv1rpc/chapi/Clearinghouse.py \
	chapiv1rpc/chapi/DelegateBase.py \
	chapiv1rpc/chapi/Exceptions.py \
	chapiv1rpc/chapi/GuardBase.py \
	chapiv1rpc/chapi/HandlerBase.py \
	chapiv1rpc/chapi/MemberAuthority.py \
	chapiv1rpc/chapi/MethodContext.py \
	chapiv1rpc/chapi/Memoize.py \
	chapiv1rpc/chapi/SliceAuthority.py \
	chapiv1rpc/chapi/__init__.py \
	chapiv1rpc/plugin.py \
	chrm/ABACGuard.py \
	chrm/ArgumentCheck.py \
	chrm/CHDatabaseEngine.py \
	chrm/CHv1Guard.py \
	chrm/CHv1Implementation.py \
	chrm/CHv1PersistentImplementation.py \
	chrm/MANIFEST.json \
	chrm/ServiceRegistry.py \
	chrm/plugin.py \
	csrm/CredentialStore.py \
	csrm/MANIFEST.json \
	csrm/plugin.py \
	flaskrest/plugin.py \
	flaskrest/MANIFEST.json \
	logging/Logging.py \
	logging/MANIFEST.json \
	logging/plugin.py \
	marm/MANIFEST.json \
	marm/MAv1Guard.py \
	marm/MAv1Implementation.py \
	marm/plugin.py \
	opsmon/plugin.py \
	opsmon/MANIFEST.json \
	opsmon/OpsMon.py \
	sarm/MANIFEST.json \
	sarm/SAv1Guard.py \
	sarm/SAv1PersistentImplementation.py \
	sarm/plugin.py
