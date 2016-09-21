Name:           geni-chapi
Version:        2.17
Release:        1%{?dist}
Summary:        GENI clearinghouse
BuildArch:      noarch
License:        GENI Public License
URL:            https://github.com/GENI-NSF/geni-ch
Source:         %{name}-%{version}.tar.gz
Group:          Applications/Internet
Requires:       httpd, mod_ssl, mod_wsgi
Requires:       python-sqlalchemy, python-psycopg2
Requires:       geni-tools, postgresql
Requires:       xmlsec1, xmlsec1-openssl

# BuildRequires: gettext
# Requires(post): info
# Requires(preun): info

%description

A set of web-based services that together comprise a GENI
Clearinghouse. These services are available through an apache
web server as XML-RPC services.

%prep
%setup -q
#iconv -f iso8859-1 -t utf-8 -o ChangeLog.conv ChangeLog && mv -f ChangeLog.conv ChangeLog
#iconv -f iso8859-1 -t utf-8 -o THANKS.conv THANKS && mv -f THANKS.conv THANKS

%build
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%make_install
# Include the copyright file
# install -m 0644 debian/copyright $RPM_BUILD_ROOT/%{_defaultdocdir}/%{name}/copyright

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)

# /etc/geni-chapi
%config %{_sysconfdir}/%{name}/credential_store_policy.json
%config %{_sysconfdir}/%{name}/example-chapi.ini
%config %{_sysconfdir}/%{name}/example-parameters.json
%config %{_sysconfdir}/%{name}/logging_config.conf
%config %{_sysconfdir}/%{name}/logging_policy.json
%config %{_sysconfdir}/%{name}/member_authority_policy.json
%config %{_sysconfdir}/%{name}/slice_authority_policy.json

# /usr/lib/python2.7/site-packages
%{python_sitelib}/chapiclient/__init__.py
%{python_sitelib}/chapiclient/__init__.pyc
%{python_sitelib}/chapiclient/__init__.pyo
%{python_sitelib}/chapiclient/chapi.py
%{python_sitelib}/chapiclient/chapi.pyc
%{python_sitelib}/chapiclient/chapi.pyo

# /usr/bin
%{_bindir}/geni-add-member-attribute
%{_bindir}/geni-add-project-member
%{_bindir}/geni-add-trusted-tool
%{_bindir}/geni-assert-email
%{_bindir}/geni-delete-outside-cert
%{_bindir}/geni-disable-user
%{_bindir}/geni-enable-user
%{_bindir}/geni-ops-report
%{_bindir}/geni-remove-member-attribute
%{_bindir}/geni-remove-project-member

# /usr/sbin
%{_sbindir}/geni-add-member-privilege
%{_sbindir}/geni-check-errors
%{_sbindir}/geni-create-ma-crl
%{_sbindir}/geni-expiring-certs
%{_sbindir}/geni-init-ca
%{_sbindir}/geni-init-services
%{_sbindir}/geni-install-templates
%{_sbindir}/geni-list-idp-members
%{_sbindir}/geni-list-member-projects
%{_sbindir}/geni-list-pending-requests
%{_sbindir}/geni-revoke-member-certificate
%{_sbindir}/geni-revoke-member-privilege
%{_sbindir}/geni-sign-tool-csr

# /usr/share/geni-ch/
%{_datadir}/geni-ch/chapi/chapi/plugins/__init__.py
%{_datadir}/geni-ch/chapi/chapi/plugins/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/MANIFEST.json
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/__init__.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Clearinghouse.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Clearinghouse.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Clearinghouse.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/DelegateBase.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/DelegateBase.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/DelegateBase.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Exceptions.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Exceptions.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Exceptions.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/GuardBase.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/GuardBase.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/GuardBase.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/HandlerBase.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/HandlerBase.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/HandlerBase.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/MemberAuthority.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/MemberAuthority.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/MemberAuthority.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Memoize.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Memoize.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Memoize.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/MethodContext.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/MethodContext.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/MethodContext.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Parameters.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Parameters.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/Parameters.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/SliceAuthority.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/SliceAuthority.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/SliceAuthority.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/__init__.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/chapi/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/plugin.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/plugin.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chapiv1rpc/plugin.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/__init__.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/ABACGuard.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/ABACGuard.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/ABACGuard.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/ArgumentCheck.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/ArgumentCheck.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/ArgumentCheck.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHDatabaseEngine.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHDatabaseEngine.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHDatabaseEngine.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHv1Guard.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHv1Guard.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHv1Guard.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHv1Implementation.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHv1Implementation.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHv1Implementation.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHv1PersistentImplementation.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHv1PersistentImplementation.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/CHv1PersistentImplementation.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/MANIFEST.json
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/ServiceRegistry.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/ServiceRegistry.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/ServiceRegistry.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/plugin.py
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/plugin.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/chrm/plugin.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/csrm/__init__.py
%{_datadir}/geni-ch/chapi/chapi/plugins/csrm/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/csrm/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/csrm/CredentialStore.py
%{_datadir}/geni-ch/chapi/chapi/plugins/csrm/CredentialStore.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/csrm/CredentialStore.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/csrm/MANIFEST.json
%{_datadir}/geni-ch/chapi/chapi/plugins/csrm/plugin.py
%{_datadir}/geni-ch/chapi/chapi/plugins/csrm/plugin.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/csrm/plugin.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/flaskrest/__init__.py
%{_datadir}/geni-ch/chapi/chapi/plugins/flaskrest/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/flaskrest/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/flaskrest/MANIFEST.json
%{_datadir}/geni-ch/chapi/chapi/plugins/flaskrest/plugin.py
%{_datadir}/geni-ch/chapi/chapi/plugins/flaskrest/plugin.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/flaskrest/plugin.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/logging/__init__.py
%{_datadir}/geni-ch/chapi/chapi/plugins/logging/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/logging/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/logging/Logging.py
%{_datadir}/geni-ch/chapi/chapi/plugins/logging/Logging.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/logging/Logging.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/logging/MANIFEST.json
%{_datadir}/geni-ch/chapi/chapi/plugins/logging/plugin.py
%{_datadir}/geni-ch/chapi/chapi/plugins/logging/plugin.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/logging/plugin.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/__init__.py
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/MANIFEST.json
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/MAv1Guard.py
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/MAv1Guard.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/MAv1Guard.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/MAv1Implementation.py
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/MAv1Implementation.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/MAv1Implementation.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/plugin.py
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/plugin.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/marm/plugin.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/opsmon/__init__.py
%{_datadir}/geni-ch/chapi/chapi/plugins/opsmon/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/opsmon/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/opsmon/MANIFEST.json
%{_datadir}/geni-ch/chapi/chapi/plugins/opsmon/OpsMon.py
%{_datadir}/geni-ch/chapi/chapi/plugins/opsmon/OpsMon.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/opsmon/OpsMon.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/opsmon/plugin.py
%{_datadir}/geni-ch/chapi/chapi/plugins/opsmon/plugin.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/opsmon/plugin.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/__init__.py
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/MANIFEST.json
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/SAv1Guard.py
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/SAv1Guard.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/SAv1Guard.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/SAv1PersistentImplementation.py
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/SAv1PersistentImplementation.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/SAv1PersistentImplementation.pyo
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/plugin.py
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/plugin.pyc
%{_datadir}/geni-ch/chapi/chapi/plugins/sarm/plugin.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/ABACKeyId.py
%{_datadir}/geni-ch/chapi/chapi/tools/ABACKeyId.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/ABACKeyId.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/ABACManager.py
%{_datadir}/geni-ch/chapi/chapi/tools/ABACManager.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/ABACManager.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/CH_constants.py
%{_datadir}/geni-ch/chapi/chapi/tools/CH_constants.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/CH_constants.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/MA_constants.py
%{_datadir}/geni-ch/chapi/chapi/tools/MA_constants.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/MA_constants.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/SA_constants.py
%{_datadir}/geni-ch/chapi/chapi/tools/SA_constants.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/SA_constants.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/SpeaksFor.py
%{_datadir}/geni-ch/chapi/chapi/tools/SpeaksFor.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/SpeaksFor.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/__init__.py
%{_datadir}/geni-ch/chapi/chapi/tools/__init__.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/__init__.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/cert_utils.py
%{_datadir}/geni-ch/chapi/chapi/tools/cert_utils.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/cert_utils.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/ch_server.py
%{_datadir}/geni-ch/chapi/chapi/tools/ch_server.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/ch_server.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/ch_server.wsgi
%{_datadir}/geni-ch/chapi/chapi/tools/chapi_log.py
%{_datadir}/geni-ch/chapi/chapi/tools/chapi_log.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/chapi_log.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/chapi_utils.py
%{_datadir}/geni-ch/chapi/chapi/tools/chapi_utils.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/chapi_utils.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/client.py
%{_datadir}/geni-ch/chapi/chapi/tools/client.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/client.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/credential_tools.py
%{_datadir}/geni-ch/chapi/chapi/tools/credential_tools.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/credential_tools.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/cs_utils.py
%{_datadir}/geni-ch/chapi/chapi/tools/cs_utils.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/cs_utils.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/dbtest.py
%{_datadir}/geni-ch/chapi/chapi/tools/dbtest.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/dbtest.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/dbutils.py
%{_datadir}/geni-ch/chapi/chapi/tools/dbutils.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/dbutils.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/file_checker.py
%{_datadir}/geni-ch/chapi/chapi/tools/file_checker.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/file_checker.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/geni_constants.py
%{_datadir}/geni-ch/chapi/chapi/tools/geni_constants.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/geni_constants.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/geni_utils.py
%{_datadir}/geni-ch/chapi/chapi/tools/geni_utils.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/geni_utils.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/guard_utils.py
%{_datadir}/geni-ch/chapi/chapi/tools/guard_utils.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/guard_utils.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/manage_service_attributes.py
%{_datadir}/geni-ch/chapi/chapi/tools/manage_service_attributes.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/manage_service_attributes.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/mapped_tables.py
%{_datadir}/geni-ch/chapi/chapi/tools/mapped_tables.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/mapped_tables.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/multiclient.py
%{_datadir}/geni-ch/chapi/chapi/tools/multiclient.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/multiclient.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/pluginmanager.py
%{_datadir}/geni-ch/chapi/chapi/tools/pluginmanager.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/pluginmanager.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/policy_file_checker.py
%{_datadir}/geni-ch/chapi/chapi/tools/policy_file_checker.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/policy_file_checker.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/portal_client.py
%{_datadir}/geni-ch/chapi/chapi/tools/portal_client.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/portal_client.pyo
%{_datadir}/geni-ch/chapi/chapi/tools/test_server.py
%{_datadir}/geni-ch/chapi/chapi/tools/test_server.pyc
%{_datadir}/geni-ch/chapi/chapi/tools/test_server.pyo

# /usr/share/geni-chapi/
%{_datadir}/%{name}/sr/sql/add-wvn-eg.sql
%{_datadir}/%{name}/abac_credential.xml
%{_datadir}/%{name}/amsoil-log-out.txt
%{_datadir}/%{name}/apache-error-log-out.txt
%{_datadir}/%{name}/ch-error-log-out.txt
%{_datadir}/%{name}/chapi-log-out.txt
%{_datadir}/%{name}/db/cs/postgresql/data.sql
%{_datadir}/%{name}/db/cs/postgresql/disable_lockdown.sql
%{_datadir}/%{name}/db/cs/postgresql/enable_lockdown.sql
%{_datadir}/%{name}/db/cs/postgresql/schema.sql
%{_datadir}/%{name}/db/cs/postgresql/update-1.sql
%{_datadir}/%{name}/db/cs/postgresql/update-2.sql
%{_datadir}/%{name}/db/cs/postgresql/update-3.sql
%{_datadir}/%{name}/db/cs/postgresql/update-4.sql
%{_datadir}/%{name}/db/cs/postgresql/update-5.sql
%{_datadir}/%{name}/db/cs/postgresql/update-6.sql
%{_datadir}/%{name}/db/cs/postgresql/update-7.sql
%{_datadir}/%{name}/db/cs/postgresql/update-8.sql
%{_datadir}/%{name}/db/logging/postgresql/schema.sql
%{_datadir}/%{name}/db/logging/postgresql/update-1.sql
%{_datadir}/%{name}/db/logging/postgresql/update-2.sql
%{_datadir}/%{name}/db/logging/postgresql/update-3.sql
%{_datadir}/%{name}/db/ma/postgresql/data.sql
%{_datadir}/%{name}/db/ma/postgresql/schema.sql
%{_datadir}/%{name}/db/ma/postgresql/update-1.sql
%{_datadir}/%{name}/db/ma/postgresql/update-2.sql
%{_datadir}/%{name}/db/ma/postgresql/update-3.sql
%{_datadir}/%{name}/db/ma/postgresql/update-4.sql
%{_datadir}/%{name}/db/ma/postgresql/update-5.sql
%{_datadir}/%{name}/db/migration/migrate-assertions.sql
%{_datadir}/%{name}/db/migration/sliver-info.sql
%{_datadir}/%{name}/db/pa/postgresql/schema.sql
%{_datadir}/%{name}/db/pa/postgresql/update-1.sql
%{_datadir}/%{name}/db/pa/postgresql/update-2.sql
%{_datadir}/%{name}/db/pa/postgresql/update-3.sql
%{_datadir}/%{name}/db/pa/postgresql/update-4.sql
%{_datadir}/%{name}/db/pa/postgresql/update-5.sql
%{_datadir}/%{name}/db/sa/postgresql/README.txt
%{_datadir}/%{name}/db/sa/postgresql/schema.sql
%{_datadir}/%{name}/db/sa/postgresql/update-1.sql
%{_datadir}/%{name}/db/sa/postgresql/update-2.sql
%{_datadir}/%{name}/db/sa/postgresql/update-3.sql
%{_datadir}/%{name}/db/sr/postgresql/README.txt
%{_datadir}/%{name}/db/sr/postgresql/schema.sql
%{_datadir}/%{name}/db/sr/postgresql/update-1.sql
%{_datadir}/%{name}/db/sr/postgresql/update-2.sql
%{_datadir}/%{name}/db/sr/postgresql/update-3.sql
%{_datadir}/%{name}/db/sr/postgresql/update-4.sql
%{_datadir}/%{name}/db/sr/postgresql/update-5.sql
%{_datadir}/%{name}/project_credential.xml
%{_datadir}/%{name}/templates/apache2.conf.tmpl
%{_datadir}/%{name}/templates/ch-ssl.conf.tmpl
%{_datadir}/%{name}/templates/chapi.ini.tmpl
%{_datadir}/%{name}/templates/install_postgresql.sh
%{_datadir}/%{name}/templates/install_service_registry.sql.tmpl
%{_datadir}/%{name}/templates/openssl.cnf.tmpl
%{_datadir}/%{name}/templates/services.ini.tmpl
%{_datadir}/%{name}/templates/templates.json
%{_datadir}/%{name}/sr/certs/al2s-ca.pem
%{_datadir}/%{name}/sr/certs/al2s.pem
%{_datadir}/%{name}/sr/certs/apt-boss.pem
%{_datadir}/%{name}/sr/certs/apt-cm.pem
%{_datadir}/%{name}/sr/certs/cenic-ig-boss.pem
%{_datadir}/%{name}/sr/certs/cenic-ig-cm.pem
%{_datadir}/%{name}/sr/certs/cenic-of.pem
%{_datadir}/%{name}/sr/certs/clemson-ig-boss.pem
%{_datadir}/%{name}/sr/certs/clemson-ig-cm.pem
%{_datadir}/%{name}/sr/certs/clemson-og.pem
%{_datadir}/%{name}/sr/certs/cornell-ig-boss.pem
%{_datadir}/%{name}/sr/certs/cornell-ig-cm.pem
%{_datadir}/%{name}/sr/certs/cwru-ig-boss.pem
%{_datadir}/%{name}/sr/certs/cwru-ig-cm.pem
%{_datadir}/%{name}/sr/certs/exosm.pem
%{_datadir}/%{name}/sr/certs/fiu-eg.pem
%{_datadir}/%{name}/sr/certs/gatech-ig-boss.pem
%{_datadir}/%{name}/sr/certs/gatech-ig-cm.pem
%{_datadir}/%{name}/sr/certs/gpo-eg-of.pem
%{_datadir}/%{name}/sr/certs/gpo-eg.pem
%{_datadir}/%{name}/sr/certs/gpo-ig-boss.pem
%{_datadir}/%{name}/sr/certs/gpo-ig-cm.pem
%{_datadir}/%{name}/sr/certs/gpo-og.pem
%{_datadir}/%{name}/sr/certs/illinois-ig-boss.pem
%{_datadir}/%{name}/sr/certs/illinois-ig-cm.pem
%{_datadir}/%{name}/sr/certs/im-vw1-cm.pem
%{_datadir}/%{name}/sr/certs/im-vw1-ssl.pem
%{_datadir}/%{name}/sr/certs/im-wilab-cm.pem
%{_datadir}/%{name}/sr/certs/im-wilab-ssl.pem
%{_datadir}/%{name}/sr/certs/irods-test.pem
%{_datadir}/%{name}/sr/certs/irods.pem
%{_datadir}/%{name}/sr/certs/kansas-ig-boss.pem
%{_datadir}/%{name}/sr/certs/kansas-ig-cm.pem
%{_datadir}/%{name}/sr/certs/kettering-ig-boss.pem
%{_datadir}/%{name}/sr/certs/kettering-ig-cm.pem
%{_datadir}/%{name}/sr/certs/max-ig-boss.pem
%{_datadir}/%{name}/sr/certs/max-ig-cm.pem
%{_datadir}/%{name}/sr/certs/max.pem
%{_datadir}/%{name}/sr/certs/missouri-ig-boss.pem
%{_datadir}/%{name}/sr/certs/missouri-ig-cm.pem
%{_datadir}/%{name}/sr/certs/moxi-ig-boss.pem
%{_datadir}/%{name}/sr/certs/moxi-ig-cm.pem
%{_datadir}/%{name}/sr/certs/moxi-of.pem
%{_datadir}/%{name}/sr/certs/nicta-eg.pem
%{_datadir}/%{name}/sr/certs/northwestern-ig-boss.pem
%{_datadir}/%{name}/sr/certs/northwestern-ig-cm.pem
%{_datadir}/%{name}/sr/certs/nps-ig-boss.pem
%{_datadir}/%{name}/sr/certs/nps-ig-cm.pem
%{_datadir}/%{name}/sr/certs/nysernet-ig-boss.pem
%{_datadir}/%{name}/sr/certs/nysernet-ig-cm.pem
%{_datadir}/%{name}/sr/certs/nysernet-of.pem
%{_datadir}/%{name}/sr/certs/nyu-ig-boss.pem
%{_datadir}/%{name}/sr/certs/nyu-ig-cm.pem
%{_datadir}/%{name}/sr/certs/ohmetrodc-ig-boss.pem
%{_datadir}/%{name}/sr/certs/ohmetrodc-ig-cm.pem
%{_datadir}/%{name}/sr/certs/osf-eg-of.pem
%{_datadir}/%{name}/sr/certs/osf-eg.pem
%{_datadir}/%{name}/sr/certs/renci-eg-of.pem
%{_datadir}/%{name}/sr/certs/renci-eg.pem
%{_datadir}/%{name}/sr/certs/rutgers-ig-boss.pem
%{_datadir}/%{name}/sr/certs/rutgers-ig-cm.pem
%{_datadir}/%{name}/sr/certs/sl-eg-of.pem
%{_datadir}/%{name}/sr/certs/sl-eg.pem
%{_datadir}/%{name}/sr/certs/sl-of.pem
%{_datadir}/%{name}/sr/certs/sox-ig-boss.pem
%{_datadir}/%{name}/sr/certs/sox-ig-cm.pem
%{_datadir}/%{name}/sr/certs/sox-of.pem
%{_datadir}/%{name}/sr/certs/stanford-ig-boss.pem
%{_datadir}/%{name}/sr/certs/stanford-ig-cm.pem
%{_datadir}/%{name}/sr/certs/tamu-eg-of.pem
%{_datadir}/%{name}/sr/certs/tamu-eg.pem
%{_datadir}/%{name}/sr/certs/ucdavis-eg-of.pem
%{_datadir}/%{name}/sr/certs/ucdavis-eg.pem
%{_datadir}/%{name}/sr/certs/uchicago-ig-boss.pem
%{_datadir}/%{name}/sr/certs/uchicago-ig-cm.pem
%{_datadir}/%{name}/sr/certs/ucla-ig-boss.pem
%{_datadir}/%{name}/sr/certs/ucla-ig-cm.pem
%{_datadir}/%{name}/sr/certs/ufl-eg-of.pem
%{_datadir}/%{name}/sr/certs/ufl-eg.pem
%{_datadir}/%{name}/sr/certs/uh-eg.pem
%{_datadir}/%{name}/sr/certs/ukl-og.pem
%{_datadir}/%{name}/sr/certs/uky-ig-boss.pem
%{_datadir}/%{name}/sr/certs/uky-ig-cm.pem
%{_datadir}/%{name}/sr/certs/uky-pg-boss.pem
%{_datadir}/%{name}/sr/certs/uky-pg-cm.pem
%{_datadir}/%{name}/sr/certs/ukypks2-ig-boss.pem
%{_datadir}/%{name}/sr/certs/ukypks2-ig-cm.pem
%{_datadir}/%{name}/sr/certs/umkc-ig-boss.pem
%{_datadir}/%{name}/sr/certs/umkc-ig-cm.pem
%{_datadir}/%{name}/sr/certs/utah-clab-boss.pem
%{_datadir}/%{name}/sr/certs/utah-clab-cm.pem
%{_datadir}/%{name}/sr/certs/utah-ig-boss.pem
%{_datadir}/%{name}/sr/certs/utah-ig-cm.pem
%{_datadir}/%{name}/sr/certs/utah-pg.pem
%{_datadir}/%{name}/sr/certs/utah-stitch-boss.pem
%{_datadir}/%{name}/sr/certs/utah-stitch-cm.pem
%{_datadir}/%{name}/sr/certs/utahddc-ig-boss.pem
%{_datadir}/%{name}/sr/certs/utahddc-ig-cm.pem
%{_datadir}/%{name}/sr/certs/utc-ig-boss.pem
%{_datadir}/%{name}/sr/certs/utc-ig-cm.pem
%{_datadir}/%{name}/sr/certs/wall2-ca.pem
%{_datadir}/%{name}/sr/certs/wall2-cm.pem
%{_datadir}/%{name}/sr/certs/wisconsin-ig-boss.pem
%{_datadir}/%{name}/sr/certs/wisconsin-ig-cm.pem
%{_datadir}/%{name}/sr/certs/wsu-eg-of.pem
%{_datadir}/%{name}/sr/certs/wsu-eg.pem
%{_datadir}/%{name}/sr/certs/wvn-eg-of.pem
%{_datadir}/%{name}/sr/certs/wvn-eg.pem
%{_datadir}/%{name}/sr/sql/add-al2s.sql
%{_datadir}/%{name}/sr/sql/add-apt.sql
%{_datadir}/%{name}/sr/sql/add-cenic-ig.sql
%{_datadir}/%{name}/sr/sql/add-cenic-of.sql
%{_datadir}/%{name}/sr/sql/add-clemson-ig.sql
%{_datadir}/%{name}/sr/sql/add-clemson-og.sql
%{_datadir}/%{name}/sr/sql/add-colorado-ig.sql
%{_datadir}/%{name}/sr/sql/add-cornell-ig.sql
%{_datadir}/%{name}/sr/sql/add-cwru-ig.sql
%{_datadir}/%{name}/sr/sql/add-exosm.sql
%{_datadir}/%{name}/sr/sql/add-fiu-eg.sql
%{_datadir}/%{name}/sr/sql/add-gatech-ig.sql
%{_datadir}/%{name}/sr/sql/add-gpo-eg-of.sql
%{_datadir}/%{name}/sr/sql/add-gpo-eg.sql
%{_datadir}/%{name}/sr/sql/add-gpo-ig.sql
%{_datadir}/%{name}/sr/sql/add-gpo-og.sql
%{_datadir}/%{name}/sr/sql/add-hawaii-ig.sql
%{_datadir}/%{name}/sr/sql/add-illinois-ig.sql
%{_datadir}/%{name}/sr/sql/add-illinois-vts.sql
%{_datadir}/%{name}/sr/sql/add-im-vw1.sql
%{_datadir}/%{name}/sr/sql/add-im-wilab.sql
%{_datadir}/%{name}/sr/sql/add-irods-test.sql
%{_datadir}/%{name}/sr/sql/add-irods.sql
%{_datadir}/%{name}/sr/sql/add-kansas-ig.sql
%{_datadir}/%{name}/sr/sql/add-kettering-ig.sql
%{_datadir}/%{name}/sr/sql/add-max-ig.sql
%{_datadir}/%{name}/sr/sql/add-max.sql
%{_datadir}/%{name}/sr/sql/add-missouri-ig.sql
%{_datadir}/%{name}/sr/sql/add-moxi-ig.sql
%{_datadir}/%{name}/sr/sql/add-moxi-of.sql
%{_datadir}/%{name}/sr/sql/add-nicta-eg.sql
%{_datadir}/%{name}/sr/sql/add-northwestern-ig.sql
%{_datadir}/%{name}/sr/sql/add-nps-ig.sql
%{_datadir}/%{name}/sr/sql/add-nps-vts.sql
%{_datadir}/%{name}/sr/sql/add-nysernet-ig.sql
%{_datadir}/%{name}/sr/sql/add-nysernet-of.sql
%{_datadir}/%{name}/sr/sql/add-nyu-ig.sql
%{_datadir}/%{name}/sr/sql/add-ohmetrodc-ig.sql
%{_datadir}/%{name}/sr/sql/add-osf-eg-of.sql
%{_datadir}/%{name}/sr/sql/add-osf-eg.sql
%{_datadir}/%{name}/sr/sql/add-princeton-ig.sql
%{_datadir}/%{name}/sr/sql/add-renci-eg-of.sql
%{_datadir}/%{name}/sr/sql/add-renci-eg.sql
%{_datadir}/%{name}/sr/sql/add-rutgers-ig.sql
%{_datadir}/%{name}/sr/sql/add-sl-eg-of.sql
%{_datadir}/%{name}/sr/sql/add-sl-eg.sql
%{_datadir}/%{name}/sr/sql/add-sl-of.sql
%{_datadir}/%{name}/sr/sql/add-sox-ig.sql
%{_datadir}/%{name}/sr/sql/add-sox-of.sql
%{_datadir}/%{name}/sr/sql/add-stanford-ig.sql
%{_datadir}/%{name}/sr/sql/add-starlight-vts.sql
%{_datadir}/%{name}/sr/sql/add-tamu-eg-of.sql
%{_datadir}/%{name}/sr/sql/add-tamu-eg.sql
%{_datadir}/%{name}/sr/sql/add-ucdavis-eg-of.sql
%{_datadir}/%{name}/sr/sql/add-ucdavis-eg.sql
%{_datadir}/%{name}/sr/sql/add-uchicago-ig.sql
%{_datadir}/%{name}/sr/sql/add-ucla-ig.sql
%{_datadir}/%{name}/sr/sql/add-ufl-eg-of.sql
%{_datadir}/%{name}/sr/sql/add-ufl-eg.sql
%{_datadir}/%{name}/sr/sql/add-uh-eg.sql
%{_datadir}/%{name}/sr/sql/add-ukl-og.sql
%{_datadir}/%{name}/sr/sql/add-uky-ig.sql
%{_datadir}/%{name}/sr/sql/add-uky-pg.sql
%{_datadir}/%{name}/sr/sql/add-ukymcv-ig.sql
%{_datadir}/%{name}/sr/sql/add-ukypks2-ig.sql
%{_datadir}/%{name}/sr/sql/add-ukypks2-vts.sql
%{_datadir}/%{name}/sr/sql/add-umich-ig.sql
%{_datadir}/%{name}/sr/sql/add-umkc-ig.sql
%{_datadir}/%{name}/sr/sql/add-utah-clab.sql
%{_datadir}/%{name}/sr/sql/add-utah-ig.sql
%{_datadir}/%{name}/sr/sql/add-utah-pg.sql
%{_datadir}/%{name}/sr/sql/add-utah-stitch.sql
%{_datadir}/%{name}/sr/sql/add-utahddc-ig.sql
%{_datadir}/%{name}/sr/sql/add-utc-ig.sql
%{_datadir}/%{name}/sr/sql/add-wall2.sql
%{_datadir}/%{name}/sr/sql/add-uwashington-ig.sql
%{_datadir}/%{name}/sr/sql/add-vt-ig.sql
%{_datadir}/%{name}/sr/sql/add-wisconsin-ig.sql
%{_datadir}/%{name}/sr/sql/add-wsu-eg-of.sql
%{_datadir}/%{name}/sr/sql/add-wsu-eg.sql
%{_datadir}/%{name}/sr/sql/add-wvn-eg-of.sql

# /usr/man
%{_mandir}/man1/geni-add-member-privilege.1.gz
%{_mandir}/man1/geni-assert-email.1.gz
%{_mandir}/man1/geni-check-errors.1.gz
%{_mandir}/man1/geni-delete-outside-cert.1.gz
%{_mandir}/man1/geni-expiring-certs.1.gz
%{_mandir}/man1/geni-install-templates.1.gz
%{_mandir}/man1/geni-list-idp-members.1.gz
%{_mandir}/man1/geni-list-member-projects.1.gz
%{_mandir}/man1/geni-list-pending-requests.1.gz
%{_mandir}/man1/geni-revoke-member-certificate.1.gz
%{_mandir}/man1/geni-revoke-member-privilege.1.gz
%{_mandir}/man1/geni-sign-tool-csr.1.gz

%changelog
* Tue Oct 27 2015 Tom Mitchell <tmitchell@bbn.com> - 2.7-1%{?dist}
- Incorporate 2.5 and 2.6 releases
* Fri Sep 18 2015 Tom Mitchell <tmitchell@bbn.com> - 2.4-2%{?dist}
- Improvements to geni-install-templates
* Thu Sep 10 2015 Tom Mitchell <tmitchell@bbn.com> - 2.4-1%{?dist}
- Update to 2.4 release
* Thu Aug 27 2015 Tom Mitchell <tmitchell@bbn.com> - 2.3-1%{?dist}
- Add dependencies
- Include templates
* Wed Aug 12 2015 Tom Mitchell <tmitchell@bbn.com> - 2.2-2%{?dist}
- Add dependencies: geni-tools, abac
- Merge final 2.2 release
* Wed Aug 12 2015 Tom Mitchell <tmitchell@bbn.com> - 2.2-1%{?dist}
- Updated RPM packaging
* Fri Jul 24 2015 Tom Mitchell <tmitchell@bbn.com> - 1.30-1%{?dist}
- Initial RPM packaging
