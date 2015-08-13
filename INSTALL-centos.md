Installation on CentOS 7
========================

Teach CentOS about the RPM repository
-------------------------------------

To teach CentOS about a new RPM repository a file can be added to
`/etc/yum.repos.d` with repository information. A sample file
might look like this:

```
[geni]
name = GENI software repository
baseurl = http://www.gpolab.bbn.com/experiment-support/gposw/centos/$releasever/os/$basearch/
```

Another approach is to publish this data for download:
```
export URL_BASE='http://www.gpolab.bbn.com/experiment-support/gposw'
curl "${URL_BASE}"/centos/geni.repo -o /etc/yum.repos.d/geni.repo
```

Installing the GENI Clearinghouse package
-----------------------------------------

Once the server knows about the RPM repository, it is easy to 
install the geni clearinghouse package:

```
yum install geni-chapi
```
