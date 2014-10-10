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
	sr/sql/add-exosm.sql \
	sr/sql/add-gpo-eg-of.sql \
	sr/sql/add-gpo-eg.sql \
	sr/sql/add-gpo-og.sql \
	sr/sql/add-nps-ig-of.sql \
	sr/sql/add-nps-ig.sql \
	sr/sql/add-osf-eg-of.sql \
	sr/sql/add-osf-eg.sql \
	sr/sql/add-princeton-ig-of.sql \
	sr/sql/add-princeton-ig.sql \
	sr/sql/add-rutgers-ig-of.sql \
	sr/sql/add-rutgers-ig.sql \
	sr/sql/add-sl-eg-of.sql \
	sr/sql/add-sl-eg.sql \
	sr/sql/add-ucdavis-eg-of.sql \
	sr/sql/add-ucdavis-eg.sql \
	sr/sql/add-ucla-ig-of.sql \
	sr/sql/add-ucla-ig.sql \
	sr/sql/add-ufl-eg-of.sql \
	sr/sql/add-ufl-eg.sql \
	sr/sql/add-ukypks2-ig-of.sql \
	sr/sql/add-ukypks2-ig.sql

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

sr/sql/add-cenic-ig-of.sql: $(srcdir)/sr/sql/add-cenic-ig-of.sql.in
sr/sql/add-cenic-ig.sql: $(srcdir)/sr/sql/add-cenic-ig.sql.in
sr/sql/add-clemson-og.sql: $(srcdir)/sr/sql/add-clemson-og.sql.in
sr/sql/add-exosm.sql: $(srcdir)/sr/sql/add-exosm.sql.in
sr/sql/add-gpo-eg-of.sql: $(srcdir)/sr/sql/add-gpo-eg-of.sql.in
sr/sql/add-gpo-eg.sql: $(srcdir)/sr/sql/add-gpo-eg.sql.in
sr/sql/add-gpo-og.sql: $(srcdir)/sr/sql/add-gpo-og.sql.in
sr/sql/add-nps-ig-of.sql: $(srcdir)/sr/sql/add-nps-ig-of.sql.in
sr/sql/add-nps-ig.sql: $(srcdir)/sr/sql/add-nps-ig.sql.in
sr/sql/add-osf-eg-of.sql: $(srcdir)/sr/sql/add-osf-eg-of.sql.in
sr/sql/add-osf-eg.sql: $(srcdir)/sr/sql/add-osf-eg.sql.in
sr/sql/add-princeton-ig-of.sql: $(srcdir)/sr/sql/add-princeton-ig-of.sql.in
sr/sql/add-princeton-ig.sql: $(srcdir)/sr/sql/add-princeton-ig.sql.in
sr/sql/add-rutgers-ig-of.sql: $(srcdir)/sr/sql/add-rutgers-ig-of.sql.in
sr/sql/add-rutgers-ig.sql: $(srcdir)/sr/sql/add-rutgers-ig.sql.in
sr/sql/add-sl-eg-of.sql: $(srcdir)/sr/sql/add-sl-eg-of.sql.in
sr/sql/add-sl-eg.sql: $(srcdir)/sr/sql/add-sl-eg.sql.in
sr/sql/add-ucdavis-eg-of.sql: $(srcdir)/sr/sql/add-ucdavis-eg-of.sql.in
sr/sql/add-ucdavis-eg.sql: $(srcdir)/sr/sql/add-ucdavis-eg.sql.in
sr/sql/add-ucla-ig-of.sql: $(srcdir)/sr/sql/add-ucla-ig-of.sql.in
sr/sql/add-ucla-ig.sql: $(srcdir)/sr/sql/add-ucla-ig.sql.in
sr/sql/add-ufl-eg-of.sql: $(srcdir)/sr/sql/add-ufl-eg-of.sql.in
sr/sql/add-ufl-eg.sql: $(srcdir)/sr/sql/add-ufl-eg.sql.in
sr/sql/add-ukypks2-ig-of.sql: $(srcdir)/sr/sql/add-ukypks2-ig-of.sql.in
sr/sql/add-ukypks2-ig.sql: $(srcdir)/sr/sql/add-ukypks2-ig.sql.in


dist_srsql_DATA = $(AM_SQL)

dist_srcerts_DATA = \
	sr/certs/cenic-ig-boss.pem \
	sr/certs/cenic-ig-cm.pem \
	sr/certs/cenic-ig-of.pem \
	sr/certs/clemson-og.pem \
	sr/certs/exosm.pem \
	sr/certs/gpo-eg-of.pem \
	sr/certs/gpo-eg.pem \
	sr/certs/gpo-og.pem \
	sr/certs/nps-ig-boss.pem \
	sr/certs/nps-ig-cm.pem \
	sr/certs/nps-ig-of.pem \
	sr/certs/osf-eg-of.pem \
	sr/certs/osf-eg.pem \
	sr/certs/princeton-ig-boss.pem \
	sr/certs/princeton-ig-cm.pem \
	sr/certs/princeton-ig-of.pem \
	sr/certs/rutgers-ig-boss.pem \
	sr/certs/rutgers-ig-cm.pem \
	sr/certs/rutgers-ig-of.pem \
	sr/certs/sl-eg-of.pem \
	sr/certs/sl-eg.pem \
	sr/certs/ucdavis-eg-of.pem \
	sr/certs/ucdavis-eg.pem \
	sr/certs/ucla-ig-boss.pem \
	sr/certs/ucla-ig-cm.pem \
	sr/certs/ucla-ig-of.pem \
	sr/certs/ufl-eg-of.pem \
	sr/certs/ufl-eg.pem \
	sr/certs/ukypks2-ig-boss.pem \
	sr/certs/ukypks2-ig-cm.pem \
	sr/certs/ukypks2-ig-of.pem
