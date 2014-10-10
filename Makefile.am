## Process this file with automake to produce Makefile.in

SUBDIRS = plugins tools etc bin man data

.PHONY: $(SUBDIRS)

# TODO: change this to just $(pkgdatadir) when
#       the installation moves from geni-ch to geni-chapi
chapidir = $(pkgdatadir)/../geni-ch/chapi/chapi

# I don't know if either of this files is required on
# installation. Putting it here for backward compatibility.
# TODO: Find out if this file is needed.
dist_chapi_SCRIPTS = linkamsoil.sh

dist_pkgdata_DATA = apache2.conf fastcgi.conf

doc_DATA = INSTALL
