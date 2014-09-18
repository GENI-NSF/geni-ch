# Where Service Registry (SR) certificates get installed
srcertsdir = $(pkgdatadir)/sr/certs

# Where Service Registry (SR) sql scripts get installed
srsqldir = $(pkgdatadir)/sr/sql

edit = sed \
	-e 's|@srcertsdir[@]|$(srcertsdir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g'

AM_SQL = \
	sr/sql/add-cenic-ig.sql \
	sr/sql/add-cenic-ig-of.sql

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

sr/sql/add-cenic-ig.sql: $(srcdir)/sr/sql/add-cenic-ig.sql.in
sr/sql/add-cenic-ig-of.sql: $(srcdir)/sr/sql/add-cenic-ig-of.sql.in

dist_srsql_DATA = \
	sr/sql/add-cenic-ig.sql \
	sr/sql/add-cenic-ig-of.sql

dist_srcerts_DATA = \
	sr/certs/cenic-ig-boss.pem \
	sr/certs/cenic-ig-cm.pem \
	sr/certs/cenic-ig-of.pem
