## Process this file with automake to produce Makefile.in

SUBDIRS = plugins tools etc

.PHONY: $(SUBDIRS)

# TODO: change this to just $(pkgdatadir) when
#       the installation moves from geni-ch to geni-chapi
chapidir = $(pkgdatadir)/../geni-ch/chapi/chapi

# I don't know if either of these files is required on
# installation. Putting them here for backward compatibility.
# TODO: Find out if these files are needed.
dist_chapi_SCRIPTS = \
	linkamsoil.sh

# This should really go in /usr/share/doc
dist_chapi_DATA = \
	INSTALL
