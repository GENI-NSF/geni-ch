Installation on CentOS 7
========================

Update the OS and install EPEL
------------------------------

```Shell
# update the OS
yum update -y

# Install the EPEL repository
yum install epel-release
```

Ensure SELinux is disabled
--------------------------

Check the status of SELinux:

```Shell
$ sestatus
SELinux status:                 disabled
```

If SELinux is enabled, do this:
```Shell
sudo sed -i -e "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config
sudo reboot
```

Teach CentOS about the GENI RPM repository
------------------------------------------

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
yum install geni-chapi --nogpgcheck -y
```

Install and configure postfix
-----------------------------

```Shell
yum install -y postfix
```

Configure postfix for this host:

```Shell
postconf myhostname=<FQDN>
postconf mydomain=<DN>
postconf myorigin=\$mydomain

# if you see warnings about IPv6:
postconf inet_protocols=ipv4
```

Create postfix user and postdrop group. See `main.cf` for details.

```Shell
useradd -r postfix
groupadd -r postdrop
```

Set file and directory permissions

```Shell
postfix set-permissions

# If this file exists, delete it
rm /var/lib/postfix/master.lock
```

Enable and start postfix

```Shell
systemctl enable postfix.service
systemctl start postfix.service
```

Test it out:
```Shell
echo "Body of the mail." | mail -s "Hello world" <email address>
```

Add portal as a trusted tool
----------------------------

```Shell
geni-add-trusted-tool -d portal -u portal -p portal --host localhost \
    'GENI Portal' urn:publicid:IDN+ch-tm.geni.net+authority+portal
```

Testing with a portal
---------------------

Get the portal cert/key

Get the KM cert/key

Edit settings.php (or ini) to point to the new service registry
