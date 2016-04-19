## Process this file with automake to produce Makefile.in

SUBDIRS = plugins tools etc bin man data db templates

.PHONY: $(SUBDIRS)

# TODO: change this to just $(pkgdatadir) when
#       the installation moves from geni-ch to geni-chapi
chapidir = $(pkgdatadir)/../geni-ch/chapi/chapi

dist_pkgdata_DATA = apache2.conf fastcgi.conf
