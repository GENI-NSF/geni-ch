dist_pkgdata_DATA = \
	abac_credential.xml \
	project_credential.xml

# Where Service Registry (SR) certificates get installed
srcertsdir = $(pkgdatadir)/sr/certs

# Where Service Registry (SR) sql scripts get installed
srsqldir = $(pkgdatadir)/sr/sql

edit = sed \
	-e 's|@srcertsdir[@]|$(srcertsdir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g'

AM_SQL = \
	sr/sql/add-al2s.sql \
	sr/sql/add-cenic-ig.sql \
	sr/sql/add-clemson-ig.sql \
	sr/sql/add-colorado-ig.sql \
	sr/sql/add-cornell-ig.sql \
	sr/sql/add-cwru-ig.sql \
	sr/sql/add-gatech-ig.sql \
	sr/sql/add-gpo-ig.sql \
	sr/sql/add-hawaii-ig.sql \
	sr/sql/add-illinois-ig.sql \
	sr/sql/add-illinois-vts.sql \
	sr/sql/add-im-vw1.sql \
	sr/sql/add-im-wilab.sql \
	sr/sql/add-kansas-ig.sql \
	sr/sql/add-kettering-ig.sql \
	sr/sql/add-maki-pg.sql \
	sr/sql/add-max-ig.sql \
	sr/sql/add-missouri-ig.sql \
	sr/sql/add-moxi-ig.sql \
	sr/sql/add-northwestern-ig.sql \
	sr/sql/add-nysernet-ig.sql \
	sr/sql/add-nyu-ig.sql \
	sr/sql/add-ohmetrodc-ig.sql \
	sr/sql/add-osu-ig.sql \
	sr/sql/add-odu-ig.sql \
	sr/sql/add-princeton-ig.sql \
	sr/sql/add-rutgers-ig.sql \
	sr/sql/add-sox-ig.sql \
	sr/sql/add-stanford-ig.sql \
	sr/sql/add-starlight-vts.sql \
	sr/sql/add-uchicago-ig.sql \
	sr/sql/add-ucla-ig.sql \
	sr/sql/add-ucsd-ig.sql \
	sr/sql/add-umich-ig.sql \
	sr/sql/add-umkc-ig.sql \
	sr/sql/add-utc-ig.sql \
	sr/sql/add-utdallas-ig.sql \
	sr/sql/add-uvm-ig.sql \
	sr/sql/add-uwashington-ig.sql \
	sr/sql/add-vcu-ig.sql \
	sr/sql/add-vt-ig.sql \
	sr/sql/add-wall2.sql \
	sr/sql/add-wisconsin-ig.sql \

AM_SQL_IN = $(AM_SQL:%=%.in)

IRODS_SQL = \
	sr/sql/add-irods.sql \
	sr/sql/add-irods-test.sql

IRODS_SQL_IN = $(IRODS_SQL:%=%.in)

$(AM_SQL) $(IRODS_SQL): Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

$(AM_SQL_IN): sr/generate-sql sr/aggdata.csv Makefile
	rm -f $@
	sr/generate-sql -o sr/sql sr/aggdata.csv

# Distribute but do not install
EXTRA_DIST = \
	sr/generate-sql \
	sr/aggdata.csv \
	$(AM_SQL_IN) \
	$(IRODS_SQL_IN)

CLEANFILES =  \
	$(AM_SQL) \
	$(IRODS_SQL)

%: $(srcdir)/%.in

# I don't know why we have to call out add-al2s.sql separately but
# without this the make fails with a file not found error on
# 'sr/sql/add-al2s.sql.in'. None of the other files need a similar
# dependency if just this one is defined.
sr/sql/add-al2s.sql: $(srcdir)/sr/sql/add-al2s.sql.in

srsql_DATA = \
	$(AM_SQL) \
	$(IRODS_SQL)

dist_srcerts_DATA = \
	sr/certs/al2s.pem \
	sr/certs/al2s-ca.pem \
	sr/certs/cenic-ig-boss.pem \
	sr/certs/cenic-ig-cm.pem \
	sr/certs/clemson-ig-boss.pem \
	sr/certs/clemson-ig-cm.pem \
	sr/certs/cornell-ig-boss.pem \
	sr/certs/cornell-ig-cm.pem \
	sr/certs/cwru-ig-boss.pem \
	sr/certs/cwru-ig-cm.pem \
	sr/certs/gatech-ig-boss.pem \
	sr/certs/gatech-ig-cm.pem \
	sr/certs/gpo-ig-boss.pem \
	sr/certs/gpo-ig-cm.pem \
	sr/certs/illinois-ig-boss.pem \
	sr/certs/illinois-ig-cm.pem \
	sr/certs/im-wilab-cm.pem \
	sr/certs/im-wilab-ssl.pem \
	sr/certs/im-vw1-cm.pem \
	sr/certs/im-vw1-ssl.pem \
	sr/certs/irods.pem \
	sr/certs/irods-test.pem \
	sr/certs/kansas-ig-boss.pem \
	sr/certs/kansas-ig-cm.pem \
	sr/certs/kettering-ig-boss.pem \
	sr/certs/kettering-ig-cm.pem \
	sr/certs/max-ig-boss.pem \
	sr/certs/max-ig-cm.pem \
	sr/certs/missouri-ig-boss.pem \
	sr/certs/missouri-ig-cm.pem \
	sr/certs/moxi-ig-boss.pem \
	sr/certs/moxi-ig-cm.pem \
	sr/certs/northwestern-ig-boss.pem \
	sr/certs/northwestern-ig-cm.pem \
	sr/certs/nysernet-ig-boss.pem \
	sr/certs/nysernet-ig-cm.pem \
	sr/certs/nyu-ig-boss.pem \
	sr/certs/nyu-ig-cm.pem \
	sr/certs/ohmetrodc-ig-boss.pem \
	sr/certs/ohmetrodc-ig-cm.pem \
	sr/certs/sox-ig-boss.pem \
	sr/certs/sox-ig-cm.pem \
	sr/certs/stanford-ig-boss.pem \
	sr/certs/stanford-ig-cm.pem \
	sr/certs/uchicago-ig-boss.pem \
	sr/certs/uchicago-ig-cm.pem \
	sr/certs/ucla-ig-boss.pem \
	sr/certs/ucla-ig-cm.pem \
	sr/certs/uky-ig-boss.pem \
	sr/certs/uky-ig-cm.pem \
	sr/certs/umkc-ig-boss.pem \
	sr/certs/umkc-ig-cm.pem \
	sr/certs/utc-ig-boss.pem \
	sr/certs/utc-ig-cm.pem \
	sr/certs/wall2-ca.pem \
	sr/certs/wall2-cm.pem \
	sr/certs/wisconsin-ig-boss.pem \
	sr/certs/wisconsin-ig-cm.pem \