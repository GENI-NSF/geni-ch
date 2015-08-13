pkgsysconfdir = $(sysconfdir)/$(PACKAGE)

dist_pkgsysconf_DATA = \
	example-chapi.ini \
	chapi-centos.ini \
        logging_config.conf \
	credential_store_policy.json \
	logging_policy.json \
	member_authority_policy.json \
	slice_authority_policy.json 

if INSTALL_GITHASH
pkgsysconf_DATA = geni-chapi-githash
endif
