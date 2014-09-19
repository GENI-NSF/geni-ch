# Where Service Registry (SR) certificates get installed
srcertsdir = $(pkgdatadir)/sr/certs

# Where Service Registry (SR) sql scripts get installed
srsqldir = $(pkgdatadir)/sr/sql

edit = sed \
	-e 's|@srcertsdir[@]|$(srcertsdir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g'

AM_SQL = \
	sr/sql/add-cenic-ig-of.sql \
	sr/sql/add-cenic-ig.sql \
	sr/sql/add-clemson-og.sql \
	sr/sql/add-osf-eg-of.sql \
	sr/sql/add-osf-eg.sql \
	sr/sql/add-princeton-ig-of.sql \
	sr/sql/add-princeton-ig.sql

AM_SQL_IN = $(AM_SQL:.sql=.sql.in)

$(AM_SQL): Makefile
	rm -f $@ $@.tmp
	srcdir=''; \
	  test -f ./$@.in || srcdir=$(srcdir)/; \
	  $(edit) $${srcdir}$@.in >$@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

$(AM_SQL_IN): sr/generate-sql sr/aggdata.csv Makefile
	rm -f $@
	sr/generate-sql -o sr/sql sr/aggdata.csv

dist_srsql_DATA = $(AM_SQL)

dist_srcerts_DATA = \
	sr/certs/cenic-ig-boss.pem \
	sr/certs/cenic-ig-cm.pem \
	sr/certs/cenic-ig-of.pem \
	sr/certs/clemson-og.pem \
	sr/certs/osf-eg-of.pem \
	sr/certs/osf-eg.pem \
	sr/certs/princeton-ig-boss.pem \
	sr/certs/princeton-ig-cm.pem \
	sr/certs/princeton-ig-of.pem
