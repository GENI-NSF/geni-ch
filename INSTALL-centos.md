Installation on CentOS 7
========================

Teach CentOS about the RPM repository
-------------------------------------

To teach CentOS about a new RPM repository a file can be added to
`/etc/yum.repos.d` with repository information. A sample file
might look like this:

```INI
[geni]
name = GENI software repository
baseurl = http://www.gpolab.bbn.com/experiment-support/gposw/centos/$releasever/os/$basearch/
```

Another approach is to publish this data for download:
```Shell
export URL_BASE='http://www.gpolab.bbn.com/experiment-support/gposw'
curl "${URL_BASE}"/centos/geni.repo -o /etc/yum.repos.d/geni.repo
```

Installing the GENI Clearinghouse package
-----------------------------------------

Once the server knows about the RPM repository, it is easy to 
install the geni clearinghouse package:

```Shell
yum install geni-chapi
```

Other installation notes
------------------------

```Shell
# Install the EPEL repository
sudo yum install epel-release

yum install httpd mod_ssl mod_fcgid

yum install python-flask python-sqlalchemy python-lxml python-psycopg2 \
         python-flup python-flask-xml-rpc
```

*Note: omitted python-pip until we need it*

*Note: omitted postgresql-client-common until we need it*
