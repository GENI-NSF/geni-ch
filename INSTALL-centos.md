Installation on CentOS 7
========================

Introduction
------------
These instructions are for installing the GENI Clearinghouse.  Information on the Clearinghouse can be found at:

http://groups.geni.net/geni/wiki/GeniClearinghouse

Update the OS
------------------------------

```Shell
# update the OS
sudo yum update -y
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

Installing the GENI Tools package
-----------------------------------------

GENI Tools RPMs are available on [GitHub](https://github.com).
`yum` can download and install these RPMs.

_N.B. The link in the example below may not be the latest RPM.
You can find the URL of the latest RPM at_
https://github.com/GENI-NSF/geni-tools/releases/latest

```Shell
sudo yum install -y \
    https://github.com/GENI-NSF/geni-tools/releases/download/v2.9/geni-tools-2.9-1.el7.centos.noarch.rpm
```

Installing the GENI Clearinghouse package
-----------------------------------------

GENI Clearinghouse RPMs are available on [GitHub](https://github.com).
`yum` can download and install these RPMs.

_N.B. The link in the example below may not be the latest RPM.
You can find the URL of the latest RPM at_
https://github.com/GENI-NSF/geni-ch/releases/latest

```Shell
sudo yum install -y \
    https://github.com/GENI-NSF/geni-ch/releases/download/v2.21/geni-chapi-2.21-1.el7.centos.noarch.rpm
```

You can see exactly what files have been installed and what directories
are used for the GENI clearinghouse using an rpm command as follows:

```bash
rpm -ql geni-chapi
```

Configure the GENI Clearinghose
-------------------------------

```Shell
sudo cp /etc/geni-chapi/example-parameters.json /etc/geni-chapi/parameters.json
```

Edit `/etc/geni-chapi/parameters.json`:
* Make sure to set `db_host` and `ch_host`!!

Do this by adding a line of the format:

```
"default" : "hostname.domain.tld"
```

to the appropriate sections of the file.

```Shell
sudo /usr/sbin/geni-install-templates
```

Install PostgreSQL database
---------------------------

If you do not already have PostgreSQL installed then you need to install it.
PostgreSQL is required for the GENI Clearinghouse.

Note: if installing on an APT centos image, do:
```Shell
sudo yum reinstall -y polkit\* power
sudo reboot
```

To install PostgreSQL on the same host as the GENI Clearinghouse,
see `/usr/share/geni-chapi/templates/install_postgresql.sh`. You should copy
that file and edit the parameters near the top to change passwords to
appropriate values for your environment. The passwords should match
those specified in `/etc/geni-chapi/parameters.json`.

Set up environment
------------------

```Shell
CH_DIR=/usr/share/geni-ch
CHAPI_DIR=/usr/share/geni-chapi
CH_HOST=`geni-install-templates --print_parameter ch_host`
DB_HOST=`geni-install-templates --print_parameter db_host`
DB_USER=`geni-install-templates --print_parameter db_user`
DB_DATABASE=`geni-install-templates --print_parameter db_name`
DB_PASSWORD=`geni-install-templates --print_parameter db_pass`

echo "$DB_HOST:*:$DB_DATABASE:$DB_USER:$DB_PASSWORD"  > ~/.pgpass
chmod 0600 ~/.pgpass

PSQL="psql -U $DB_USER -h $DB_HOST $DB_DATABASE"
```

If you log out and log back in again you may need to set these environment
variables again. Another approach is to add these values to your shell
init file (`.bashrc`, `.cshrc`, etc.) as appropriate so that the values
are set each time you log in.

Initialize Database
-------------------

```Shell
for sch in cs logging ma pa sa sr
do
    $PSQL -f $CHAPI_DIR/db/$sch/postgresql/schema.sql
done

for data in $CHAPI_DIR/db/*/postgresql/data.sql
do
    $PSQL -f $data
done

$PSQL < /tmp/install_service_registry.sql
```

Set up Certificate Authority
----------------------------

```Shell
sudo mkdir -p $CH_DIR/CA
sudo mkdir -p $CH_DIR/CA/private
sudo mkdir -p $CH_DIR/CA/certs
sudo mkdir -p $CH_DIR/CA/newcerts
sudo mkdir -p $CH_DIR/CA/crl
sudo geni-init-ca /etc/geni-ch/services.ini

sudo touch $CH_DIR/CA/index.txt
echo "00" > /tmp/serial
sudo mv /tmp/serial $CH_DIR/CA/serial
sudo chown -R root.root $CH_DIR/CA
```

Initialize Services
-------------------

```Shell
for srv in sr sa pa ma logging cs km portal
do
    sudo mkdir -p $CH_DIR/$srv
done

sudo geni-init-services /etc/geni-ch/services.ini
sudo chown -R apache.apache /usr/share/geni-ch/CA
```

Set up web server SSL certificates
----------------------------------
If you have real SSL certs from a standard CA (Verisign, Cybertrust, etc.)
skip this step and configure those certificates instead.

```Shell
sudo openssl genrsa -out ch-$CH_HOST-key.pem 2048

sudo openssl req -new -key ch-$CH_HOST-key.pem -out /tmp/ch-$CH_HOST.csr \
    -subj "/C=US/ST=MA/L=Cambridge/CN=$CH_HOST"

sudo openssl x509 -req -days 365 -in /tmp/ch-$CH_HOST.csr \
    -signkey ch-$CH_HOST-key.pem -out ch-$CH_HOST-cert.pem

sudo mv ch-$CH_HOST-key.pem ch-$CH_HOST-cert.pem /etc/geni-chapi
```

Set up trusted roots
--------------------

```Shell
# Set up trusted roots
TRUSTED_ROOTS_DIR=$CH_DIR/portal/gcf.d/trusted_roots
sudo mkdir -p $TRUSTED_ROOTS_DIR
sudo ln -s $CH_DIR//CA/cacert.pem $TRUSTED_ROOTS_DIR
sudo ln -s $CH_DIR//ma/ma-cert.pem $TRUSTED_ROOTS_DIR

# Create combined cert
cat /usr/share/geni-ch/CA/cacert.pem /usr/share/geni-ch/ma/ma-cert.pem > /tmp/ca-ma-cert.pem
sudo cp /tmp/ca-ma-cert.pem /usr/share/geni-ch/CA
```

Restart httpd

```Shell
sudo systemctl start httpd.service
```

Install and configure postfix
-----------------------------

If postfix is not already installed on your host, then install/configure
it as follows. If postfix is already installed you can go to the next step.

```Shell
sudo yum install -y postfix mailx
```

Configure postfix for this host by running these commands:

```Shell
sudo postconf myhostname=`hostname -f`
sudo postconf mydomain=`hostname -d`
sudo postconf myorigin=\$mydomain

# if you see warnings about IPv6:
sudo postconf inet_protocols=ipv4
```

Create postfix user and postdrop group. See `main.cf` for details.

```Shell
sudo useradd -r postfix
sudo groupadd -r postdrop
```

Set file and directory permissions

```Shell
sudo postfix set-permissions

# If this file exists, delete it
sudo rm /var/lib/postfix/master.lock
```

Enable and start postfix

```Shell
sudo systemctl enable postfix.service
sudo systemctl start postfix.service
```

Test it out:
```Shell
echo "Body of the mail." | mail -s "Hello world" <email address>
```

Test Clearinghouse APIs
-----------------------

Test Service Registry (port 8444)
```Shell
python /usr/share/geni-ch/chapi/chapi/tools/client.py \
       --cert /usr/share/geni-ch/ma/ma-cert.pem  \
       --key /usr/share/geni-ch/ma/ma-key.pem  \
       --url https://$CH_HOST:8444/SR --method get_services
```

Test Slice Authority (port 443)
```Shell
python /usr/share/geni-ch/chapi/chapi/tools/client.py \
       --cert /usr/share/geni-ch/ma/ma-cert.pem \
       --key /usr/share/geni-ch/ma/ma-key.pem \
       --url https://$CH_HOST/SA --method get_version
```

Add portal as a trusted tool
----------------------------

When you have a GENI Portal that you want to test with this Clearinghouse
you must configure the Clearinghouse to expect communication from the
portal. Use this command,

```Shell
AUTHORITY=`geni-install-templates --print_parameter ch_authority`
PORTAL_URN=urn:publicid:IDN+${AUTHORITY}+authority+portal

geni-add-trusted-tool -d portal -u portal -p portal --host localhost \
    'GENI Portal' "${PORTAL_URN}"
```

Open up Firewall if necessary
-----------------------------
If your machine is running firewall software it may be necessary for you to add rules to allow connections to the Clearinghouse.  The ports that need to be open are 22(SSH), 80(HTTP), 443(HTTPS) and 8444(Clearinghouse).

Enable HTTPD and SHIBD services to start at boot time
-----------------------------------------------------

The following command will enable the HTTPD service (Apache) to start
at boot time:

````sh
sudo systemctl enable httpd.service
````

The following command will verify that the HTTPD service is set to start
at boot time. This should report "enabled".

````sh
sudo systemctl is-enabled httpd.service
````
