#!/bin/bash
#
# Temporarily, Go to test suite branch
git checkout -b tkt504_test_suite

# Update / Install required packages
sudo apt-get install -y python-sqlalchemy python-lxml python-psycopg2
# postgresql is already installed

# Set up database
echo "createdb chtest" > /tmp/createdb.sh
echo "createuser -S -D -R chtest" >> /tmp/createdb.sh
echo "psql -c 'GRANT ALL PRIVILEGES on database chtest to chtest'" >> /tmp/createdb.sh
echo "psql -c \"ALTER USER chtest WITH PASSWORD 'chtest'\"" >> /tmp/createdb.sh

sudo su - postgres < /tmp/createdb.sh
echo "localhost:*:chtest:chtest:chtest" > ~/.pgpass
chmod 0600 ~/.pgpass

# Setup script variables
HOME=`pwd`
HOSTNAME=`hostname -f`
DATADIR=/usr/share/geni-ch
CHAPIDIR=$HOME
PSQL="psql -U chtest -h localhost chtest"

# Install CH
cd $CHAPIDIR
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --bindir=/usr/local/bin \
    --sbindir=/usr/local/sbin --mandir=/usr/local/man --enable-gpo-lab
make
sudo make install

# Set up CA
sudo mkdir -p /usr/share/geni-ch/CA/private
sudo cp $CHAPIDIR/templates/openssl.cnf.tmpl /usr/share/geni-ch/CA/openssl.cnf
sudo $CHAPIDIR/bin/init-ca
sudo mkdir $DATADIR/CA/newcerts
sudo touch $DATADIR/CA/index.txt
echo "01" > /tmp/serial; sudo mv /tmp/serial $DATADIR/CA
sudo chmod a+w /usr/share/geni-ch/CA/newcerts
sudo chmod a+w /usr/share/geni-ch/CA/private
sudo chmod a+w /usr/share/geni-ch/CA/serial
sudo chmod a+w /usr/share/geni-ch/CA

# Set up GENI CH services
cp $CHAPIDIR/templates/services.ini.tmpl /tmp/services.ini

sed -i "s/@ch_admin_email@/www-data@localhost/g" /tmp/services.ini
sed -i "s/@ch_authority@/$HOSTNAME/g" /tmp/services.ini
sed -i "s/@ch_host@/$HOSTNAME/g" /tmp/services.ini
sed -i "s/@pkgdatadir@/\/usr\/share\/geni-ch/g" /tmp/services.ini
sed -i "s/@datadir@/\/usr\/share\/geni-ch/g" /tmp/services.ini

sudo mkdir $DATADIR/sr
sudo mkdir $DATADIR/ma
sudo mkdir $DATADIR/sa
sudo mkdir $DATADIR/pa
sudo mkdir $DATADIR/logging
sudo mkdir $DATADIR/cs
sudo mkdir $DATADIR/km
sudo mkdir $DATADIR/portal
sudo $CHAPIDIR/bin/geni-init-services /tmp/services.ini

echo "CONTENTS of /usr/share/geni-ch"
find . -name /usr/share/geni-ch

# Set up trusted roots
sudo mkdir -p $DATADIR/portal/gcf.d/trusted_roots
cat $DATADIR/CA/cacert.pem $DATADIR/ma/ma-cert.pem > /tmp/CATedCACerts.pem
sudo mv /tmp/CATedCACerts.pem $DATADIR/portal/gcf.d/trusted_roots

# Set up database
for sch in cs logging ma pa sa sr
do
    $PSQL -f $CHAPIDIR/db/$sch/postgresql/schema.sql
done

for data in $CHAPIDIR/db/*/postgresql/data.sql
do
    $PSQL -f $data
done

cp $CHAPIDIR/templates/install_service_registry.sql.tmpl /tmp/install_service_registry.sql
sed -i "s/@ch_host@/$HOSTNAME/g" /tmp/install_service_registry.sql
$PSQL < /tmp/install_service_registry.sql



# Set up chapi.ini
sudo cp $CHAPIDIR/templates/chapi.ini.tmpl /etc/geni-chapi/chapi.ini
sudo sed -i "s/@pkgdatadir@/\/usr\/share\/geni-ch/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@pkgsysconfdir@/\/usr\/share\/geni-ch/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@ch_admin_email@/www-data@localhost/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@ch_authority@/$HOSTNAME/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_user@/chtest/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_pass@/chtest/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_host@/localhost/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_name@/chtest/g" /etc/geni-chapi/chapi.ini

# Set up mail server
sudo debconf-set-selections <<< "postfix postfix/mailname string $HOSTNAME"
sudo debconf-set-selections <<<"postfix postfix/main_mailer_type string 'Local Only'"
sudo apt-get install -y postfix # Use the local option
sudo postconf myhostname=`hostname -f`
sudo postconf mydomain=`hostname -d`
sudo postconf myorigin=\$mydomain
sudo postconf inet_protocols=ipv4
sudo postfix set-permissions
sudo rm /var/lib/postfix/master.lock
sudo service postfix restart

# pwd = /home/travis/build/GENI-NSF/geni-ch/geni-ch
# whomi = travis

# Set up runtime
export PYTHONPATH=$PYTHONPATH:$CHAPIDIR

# Start test CH server
$CHAPIDIR/tools/test_server.py >& /tmp/test_server.log &



# When testing is done, run 
# kill %1 or killall python to kill the server
