# Where Service Registry (SR) certificates get installed
srcertsdir = $(pkgdatadir)/sr/certs

# Where Service Registry (SR) sql scripts get installed
srsqldir = $(pkgdatadir)/sr/sql

edit = sed \
	-e 's|@srcertsdir[@]|$(srcertsdir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g'

AM_SQL = \
	sr/sql/add-al2s.sql \
	sr/sql/add-apt.sql \
	sr/sql/add-cenic-ig-of.sql \
	sr/sql/add-cenic-ig.sql \
	sr/sql/add-clemson-ig-of.sql \
	sr/sql/add-clemson-ig.sql \
	sr/sql/add-clemson-og.sql \
	sr/sql/add-colorado-ig-of.sql \
	sr/sql/add-colorado-ig.sql \
	sr/sql/add-cwru-ig.sql \
	sr/sql/add-exosm.sql \
	sr/sql/add-gatech-ig-of.sql \
	sr/sql/add-gatech-ig.sql \
	sr/sql/add-gpo-eg-of.sql \
	sr/sql/add-gpo-eg.sql \
	sr/sql/add-gpo-og.sql \
	sr/sql/add-im-wilab.sql \
	sr/sql/add-im-vw1.sql \
	sr/sql/add-moxi-ig-of.sql \
	sr/sql/add-moxi-ig.sql \
	sr/sql/add-moxi-of.sql \
	sr/sql/add-nicta-eg.sql \
	sr/sql/add-nps-ig-of.sql \
	sr/sql/add-nps-ig.sql \
	sr/sql/add-ohmetrodc-ig-of.sql \
	sr/sql/add-ohmetrodc-ig.sql \
	sr/sql/add-osf-eg-of.sql \
	sr/sql/add-osf-eg.sql \
	sr/sql/add-princeton-ig-of.sql \
	sr/sql/add-princeton-ig.sql \
	sr/sql/add-renci-eg-of.sql \
	sr/sql/add-renci-eg.sql \
	sr/sql/add-rutgers-ig-of.sql \
	sr/sql/add-rutgers-ig.sql \
	sr/sql/add-sl-eg-of.sql \
	sr/sql/add-sl-eg.sql \
	sr/sql/add-sox-ig-of.sql \
	sr/sql/add-sox-ig.sql \
	sr/sql/add-tamu-eg-of.sql \
	sr/sql/add-tamu-eg.sql \
	sr/sql/add-ucdavis-eg-of.sql \
	sr/sql/add-ucdavis-eg.sql \
	sr/sql/add-uchicago-ig-of.sql \
	sr/sql/add-uchicago-ig.sql \
	sr/sql/add-ucla-ig-of.sql \
	sr/sql/add-ucla-ig.sql \
	sr/sql/add-ufl-eg-of.sql \
	sr/sql/add-ufl-eg.sql \
	sr/sql/add-ukypks2-ig-of.sql \
	sr/sql/add-ukypks2-ig.sql \
	sr/sql/add-uky-ig-of.sql \
	sr/sql/add-uky-ig.sql \
	sr/sql/add-umkc-ig-of.sql \
	sr/sql/add-umkc-ig.sql \
	sr/sql/add-utah-clab.sql \
	sr/sql/add-utah-stitch.sql \
	sr/sql/add-utc-ig-of.sql \
	sr/sql/add-utc-ig.sql \
	sr/sql/add-uwashington-ig-of.sql \
	sr/sql/add-uwashington-ig.sql \
	sr/sql/add-wall2.sql \
	sr/sql/add-wsu-eg-of.sql \
	sr/sql/add-wsu-eg.sql \
	sr/sql/add-wvn-eg-of.sql \
	sr/sql/add-wvn-eg.sql

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

# Distribute but do not install
EXTRA_DIST = \
	sr/generate-sql \
	sr/aggdata.csv \
	$(AM_SQL_IN)

CLEANFILES =  \
	$(AM_SQL)

sr/sql/add-al2s.sql: $(srcdir)/sr/sql/add-al2s.sql.in
sr/sql/add-apt.sql: $(srcdir)/sr/sql/add-apt.sql.in
sr/sql/add-cenic-ig-of.sql: $(srcdir)/sr/sql/add-cenic-ig-of.sql.in
sr/sql/add-cenic-ig.sql: $(srcdir)/sr/sql/add-cenic-ig.sql.in
sr/sql/add-clemson-ig-of.sql: $(srcdir)/sr/sql/add-clemson-ig-of.sql.in
sr/sql/add-clemson-ig.sql: $(srcdir)/sr/sql/add-clemson-ig.sql.in
sr/sql/add-clemson-og.sql: $(srcdir)/sr/sql/add-clemson-og.sql.in
sr/sql/add-colorado-ig-of.sql: $(srcdir)/sr/sql/add-colorado-ig-of.sql.in
sr/sql/add-colorado-ig.sql: $(srcdir)/sr/sql/add-colorado-ig.sql.in
sr/sql/add-cwru-ig.sql: $(srcdir)/sr/sql/add-cwru-ig.sql.in
sr/sql/add-exosm.sql: $(srcdir)/sr/sql/add-exosm.sql.in
sr/sql/add-gatech-ig-of.sql: $(srcdir)/sr/sql/add-colorado-ig-of.sql.in
sr/sql/add-gatech-ig.sql: $(srcdir)/sr/sql/add-colorado-ig.sql.in
sr/sql/add-gpo-eg-of.sql: $(srcdir)/sr/sql/add-gpo-eg-of.sql.in
sr/sql/add-gpo-eg.sql: $(srcdir)/sr/sql/add-gpo-eg.sql.in
sr/sql/add-gpo-og.sql: $(srcdir)/sr/sql/add-gpo-og.sql.in
sr/sql/add-im-wilab.sql: $(srcdir)/sr/sql/add-im-wilab.sql.in
sr/sql/add-im-vw1.sql: $(srcdir)/sr/sql/add-im-vw1.sql.in
sr/sql/add-moxi-ig-of.sql: $(srcdir)/sr/sql/add-moxi-ig-of.sql.in
sr/sql/add-moxi-ig.sql: $(srcdir)/sr/sql/add-moxi-ig.sql.in
sr/sql/add-moxi-of.sql: $(srcdir)/sr/sql/add-moxi-of.sql.in
sr/sql/add-nicta-eg.sql: $(srcdir)/sr/sql/add-nicta-eg.sql.in
sr/sql/add-nps-ig-of.sql: $(srcdir)/sr/sql/add-nps-ig-of.sql.in
sr/sql/add-nps-ig.sql: $(srcdir)/sr/sql/add-nps-ig.sql.in
sr/sql/add-ohmetrodc-ig-of.sql: $(srcdir)/sr/sql/add-ohmetrodc-ig-of.sql.in
sr/sql/add-ohmetrodc-ig.sql: $(srcdir)/sr/sql/add-ohmetrodc-ig.sql.in
sr/sql/add-osf-eg-of.sql: $(srcdir)/sr/sql/add-osf-eg-of.sql.in
sr/sql/add-osf-eg.sql: $(srcdir)/sr/sql/add-osf-eg.sql.in
sr/sql/add-princeton-ig-of.sql: $(srcdir)/sr/sql/add-princeton-ig-of.sql.in
sr/sql/add-princeton-ig.sql: $(srcdir)/sr/sql/add-princeton-ig.sql.in
sr/sql/add-renci-eg-of.sql: $(srcdir)/sr/sql/add-renci-eg-of.sql.in
sr/sql/add-renci-eg.sql: $(srcdir)/sr/sql/add-renci-eg.sql.in
sr/sql/add-rutgers-ig-of.sql: $(srcdir)/sr/sql/add-rutgers-ig-of.sql.in
sr/sql/add-rutgers-ig.sql: $(srcdir)/sr/sql/add-rutgers-ig.sql.in
sr/sql/add-sl-eg-of.sql: $(srcdir)/sr/sql/add-sl-eg-of.sql.in
sr/sql/add-sl-eg.sql: $(srcdir)/sr/sql/add-sl-eg.sql.in
sr/sql/add-sox-ig-of.sql: $(srcdir)/sr/sql/add-sox-ig-of.sql.in
sr/sql/add-sox-ig.sql: $(srcdir)/sr/sql/add-sox-ig.sql.in
sr/sql/add-tamu-eg-of.sql: $(srcdir)/sr/sql/add-tamu-eg-of.sql.in
sr/sql/add-tamu-eg.sql: $(srcdir)/sr/sql/add-tamu-eg.sql.in
sr/sql/add-ucdavis-eg-of.sql: $(srcdir)/sr/sql/add-ucdavis-eg-of.sql.in
sr/sql/add-ucdavis-eg.sql: $(srcdir)/sr/sql/add-ucdavis-eg.sql.in
sr/sql/add-uchicago-ig-of.sql: $(srcdir)/sr/sql/add-uchicago-ig-of.sql.in
sr/sql/add-uchicago-ig.sql: $(srcdir)/sr/sql/add-uchicago-ig.sql.in
sr/sql/add-ucla-ig-of.sql: $(srcdir)/sr/sql/add-ucla-ig-of.sql.in
sr/sql/add-ucla-ig.sql: $(srcdir)/sr/sql/add-ucla-ig.sql.in
sr/sql/add-ufl-eg-of.sql: $(srcdir)/sr/sql/add-ufl-eg-of.sql.in
sr/sql/add-ufl-eg.sql: $(srcdir)/sr/sql/add-ufl-eg.sql.in
sr/sql/add-uky-ig-of.sql: $(srcdir)/sr/sql/add-uky-ig-of.sql.in
sr/sql/add-uky-ig.sql: $(srcdir)/sr/sql/add-uky-ig.sql.in
sr/sql/add-ukypks2-ig-of.sql: $(srcdir)/sr/sql/add-ukypks2-ig-of.sql.in
sr/sql/add-ukypks2-ig.sql: $(srcdir)/sr/sql/add-ukypks2-ig.sql.in
sr/sql/add-umkc-ig-of.sql: $(srcdir)/sr/sql/add-umkc-ig-of.sql.in
sr/sql/add-umkc-ig.sql: $(srcdir)/sr/sql/add-umkc-ig.sql.in
sr/sql/add-utah-clab.sql: $(srcdir)/sr/sql/add-utah-clab.sql.in
sr/sql/add-utah-stitch.sql: $(srcdir)/sr/sql/add-utah-stitch.sql.in
sr/sql/add-utc-ig-of.sql: $(srcdir)/sr/sql/add-utc-ig-of.sql.in
sr/sql/add-utc-ig.sql: $(srcdir)/sr/sql/add-utc-ig.sql.in
sr/sql/add-uwashington-ig-of.sql: $(srcdir)/sr/sql/add-uwashington-ig-of.sql.in
sr/sql/add-uwashington-ig.sql: $(srcdir)/sr/sql/add-uwashington-ig.sql.in
sr/sql/add-wall2.sql: $(srcdir)/sr/sql/add-wall2.sql.in
sr/sql/add-wsu-eg-of.sql: $(srcdir)/sr/sql/add-wsu-eg-of.sql.in
sr/sql/add-wsu-eg.sql: $(srcdir)/sr/sql/add-wsu-eg.sql.in
sr/sql/add-wvn-eg-of.sql: $(srcdir)/sr/sql/add-wvn-eg-of.sql.in
sr/sql/add-wvn-eg.sql: $(srcdir)/sr/sql/add-wvn-eg.sql.in


srsql_DATA = $(AM_SQL)

dist_srcerts_DATA = \
	sr/certs/al2s.pem \
	sr/certs/al2s-ca.pem \
	sr/certs/apt-boss.pem \
	sr/certs/apt-cm.pem \
	sr/certs/cenic-ig-boss.pem \
	sr/certs/cenic-ig-cm.pem \
	sr/certs/cenic-ig-of.pem \
	sr/certs/clemson-ig-boss.pem \
	sr/certs/clemson-ig-cm.pem \
	sr/certs/clemson-ig-of.pem \
	sr/certs/clemson-og.pem \
	sr/certs/colorado-ig-boss.pem \
	sr/certs/colorado-ig-cm.pem \
	sr/certs/colorado-ig-of.pem \
	sr/certs/cwru-ig-boss.pem \
	sr/certs/cwru-ig-cm.pem \
	sr/certs/exosm.pem \
	sr/certs/gatech-ig-boss.pem \
	sr/certs/gatech-ig-cm.pem \
	sr/certs/gatech-ig-of.pem \
	sr/certs/gpo-eg-of.pem \
	sr/certs/gpo-eg.pem \
	sr/certs/gpo-ig-boss.pem \
	sr/certs/gpo-ig-cm.pem \
	sr/certs/gpo-ig-of.pem \
	sr/certs/gpo-og.pem \
	sr/certs/im-wilab-cm.pem \
	sr/certs/im-wilab-ssl.pem \
	sr/certs/im-vw1-cm.pem \
	sr/certs/im-vw1-ssl.pem \
	sr/certs/moxi-ig-boss.pem \
	sr/certs/moxi-ig-cm.pem \
	sr/certs/moxi-ig-of.pem \
	sr/certs/moxi-of.pem \
	sr/certs/nicta-eg.pem \
	sr/certs/nps-ig-boss.pem \
	sr/certs/nps-ig-cm.pem \
	sr/certs/nps-ig-of.pem \
	sr/certs/ohmetrodc-ig-boss.pem \
	sr/certs/ohmetrodc-ig-cm.pem \
	sr/certs/ohmetrodc-ig-of.pem \
	sr/certs/osf-eg-of.pem \
	sr/certs/osf-eg.pem \
	sr/certs/princeton-ig-boss.pem \
	sr/certs/princeton-ig-cm.pem \
	sr/certs/princeton-ig-of.pem \
	sr/certs/renci-eg-of.pem \
	sr/certs/renci-eg.pem \
	sr/certs/rutgers-ig-boss.pem \
	sr/certs/rutgers-ig-cm.pem \
	sr/certs/rutgers-ig-of.pem \
	sr/certs/sl-eg-of.pem \
	sr/certs/sl-eg.pem \
	sr/certs/sox-ig-boss.pem \
	sr/certs/sox-ig-cm.pem \
	sr/certs/sox-ig-of.pem \
	sr/certs/tamu-eg-of.pem \
	sr/certs/tamu-eg.pem \
	sr/certs/ucdavis-eg-of.pem \
	sr/certs/ucdavis-eg.pem \
	sr/certs/uchicago-ig-boss.pem \
	sr/certs/uchicago-ig-cm.pem \
	sr/certs/uchicago-ig-of.pem \
	sr/certs/ucla-ig-boss.pem \
	sr/certs/ucla-ig-cm.pem \
	sr/certs/ucla-ig-of.pem \
	sr/certs/ufl-eg-of.pem \
	sr/certs/ufl-eg.pem \
	sr/certs/uky-ig-boss.pem \
	sr/certs/uky-ig-cm.pem \
	sr/certs/uky-ig-of.pem \
	sr/certs/uky-pg.pem \
	sr/certs/ukypks2-ig-boss.pem \
	sr/certs/ukypks2-ig-cm.pem \
	sr/certs/ukypks2-ig-of.pem \
	sr/certs/umkc-ig-boss.pem \
	sr/certs/umkc-ig-cm.pem \
	sr/certs/umkc-ig-of.pem \
	sr/certs/utah-ig-boss.pem \
	sr/certs/utah-ig-cm.pem \
	sr/certs/utah-ig-of.pem \
	sr/certs/utah-clab-boss.pem \
	sr/certs/utah-clab-cm.pem \
	sr/certs/utah-pg.pem \
	sr/certs/utah-stitch-boss.pem \
	sr/certs/utah-stitch-cm.pem \
	sr/certs/utc-ig-boss.pem \
	sr/certs/utc-ig-cm.pem \
	sr/certs/utc-ig-of.pem \
	sr/certs/uwashington-ig-boss.pem \
	sr/certs/uwashington-ig-cm.pem \
	sr/certs/uwashington-ig-of.pem \
	sr/certs/wall2-ca.pem \
	sr/certs/wall2-cm.pem \
	sr/certs/wsu-eg-of.pem \
	sr/certs/wsu-eg.pem \
	sr/certs/wvn-eg-of.pem \
	sr/certs/wvn-eg.pem
