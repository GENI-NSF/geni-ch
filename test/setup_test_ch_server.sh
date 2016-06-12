#!/bin/bash
#
# Temporarily, Go to test suite branch
git checkout -b tkt504_test_suite
set -x

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
AUTHORITY=testch

# Install CH
cd $CHAPIDIR
./autogen.sh >& /dev/null
./configure --prefix=/usr --sysconfdir=/etc --bindir=/usr/local/bin \
    --sbindir=/usr/local/sbin --mandir=/usr/local/man --enable-gpo-lab >& /dev/null
make >& /dev/null
sudo make install >& /dev/null

# Set up CA
sudo mkdir -p /usr/share/geni-ch/CA/private
sudo cp $CHAPIDIR/templates/openssl.cnf.tmpl $DATADIR/CA/openssl.cnf

# Create CA initialization file
echo "[ca]" > /tmp/ca.ini
echo "conf=$DATADIR/CA/openssl.cnf" >> /tmp/ca.ini
echo "cert=$DATADIR/CA/cacert.pem" >> /tmp/ca.ini
echo "key=$DATADIR/CA/private/cakey.pem" >> /tmp/ca.ini
echo "authority=$AUTHORITY" >> /tmp/ca.ini

# Inilalize GENI CH CA
sudo $CHAPIDIR/bin/geni-init-ca /tmp/ca.ini

sudo mkdir $DATADIR/CA/newcerts
sudo touch $DATADIR/CA/index.txt
echo "01" > /tmp/serial; sudo mv /tmp/serial $DATADIR/CA
sudo chmod a+w /usr/share/geni-ch/CA/newcerts
sudo chmod a+w /usr/share/geni-ch/CA/private
sudo chmod a+w /usr/share/geni-ch/CA/serial
sudo chmod a+w /usr/share/geni-ch/CA

# Set up GENI CH services
cp $CHAPIDIR/templates/services.ini.tmpl /tmp/services.ini

sed -i "s/@ch_admin_email@//g" /tmp/services.ini
sed -i "s/@ch_authority@/$AUTHORITY/g" /tmp/services.ini
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
echo "Setting up GENI services"
sudo $CHAPIDIR/bin/geni-init-services /tmp/services.ini

echo "DATADIR=$DATADIR"
cat /tmp/services.ini

# Set up trusted roots
sudo mkdir -p $DATADIR/portal/gcf.d/trusted_roots
sudo cp $DATADIR/CA/cacert.pem $DATADIR/ma/ma-cert.pem $DATADIR/portal/gcf.d/trusted_roots
cat $DATADIR/CA/cacert.pem $DATADIR/ma/ma-cert.pem > /tmp/CATedCACerts.pem
sudo mv /tmp/CATedCACerts.pem $DATADIR/portal/gcf.d/trusted_roots

sudo ls -l $DATADIR/portal/gcf.d/trusted_roots
sudo cat $DATADIR/portal/gcf.d/trusted_roots/CATedCACerts.pem

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
sudo sed -i "s/@ch_admin_email@//g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@ch_authority@/$HOSTNAME/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_user@/chtest/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_pass@/chtest/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_host@/localhost/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_name@/chtest/g" /etc/geni-chapi/chapi.ini

cat /etc/geni-chapi/chapi.ini

# Set up mail server
#sudo debconf-set-selections <<< "postfix postfix/mailname string $HOSTNAME"
#sudo debconf-set-selections <<<"postfix postfix/main_mailer_type string 'Local only'"
#sudo apt-get install -y postfix # Use the local option
#sudo apt-get install -y mailutils 
#sudo postconf myhostname=`hostname -f`
#sudo postconf mydomain=`hostname -d`
#sudo postconf myorigin=\$mydomain
#sudo postconf inet_protocols=ipv4
#sudo postfix set-permissions
#sudo rm /var/lib/postfix/master.lock
#sudo service postfix restart

# pwd = /home/travis/build/GENI-NSF/geni-ch/geni-ch
# whomi = travis

# Set up runtime
export PYTHONPATH=$PYTHONPATH:$CHAPIDIR

echo $CHAPIDIR
ls -l $CHAPIDIR/tools/test_server.py

# Start test CH server
$CHAPIDIR/tools/test_server.py >& /tmp/test_server.log &

