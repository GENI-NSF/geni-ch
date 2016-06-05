# Install GENI-CH and GENI-TOOLS
git clone https://github.com/GENI-NSF/geni-tools.git
#git clone https://github.com/GENI-NSF/geni-ch.git
git clone https://github.com/MarshallBrinn/geni-ch.git
git checkout tkt504_test_suite

# Update / Install
sudo apt-get -qq update
sudo apt-get install -y python-m2crypto python-dateutil python-openssl
sudo apt-get install -y libxmlsec1 xmlsec1 libxmlsec1-openssl libxmlsec1-dev

sudo apt-get install -y python-sqlalchemy python-lxml python-psycopg2
sudo apt-get install -y postgresql


# Set up database
sudo su - postgres
createdb chtest
createuser -W chtest
Password: chtest
psql -c "GRANT ALL PRIVILEGES on database chtest to chtest"
psql -c "ALTER USER chtest WITH PASSWORD 'chtest'"
exit
echo "localhost:*:chtest:chtest:chtest" > ~/.pgpass
chmod 0600 ~/.pgpass

HOSTNAME=`hostname -f`
DATADIR=/usr/share/geni-ch
CHAPIDIR=~/geni-ch

# Install CH
cd ~/geni-ch/bin
./autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --bindir=/usr/local/bin \
    --sbindir=/usr/local/sbin --mandir=/usr/local/man --enable-gpo-lab
make
sudo make install

# Set up CA
mkdir -p /usr/share/geni-ch/CA/private
sudo cp ~/geni-ch/templates/openssl.cnf.tmpl /usr/share/geni-ch/CA/openssl.cnf
sudo ./install-ca
sudo mkdir $DATADIR/CA/newcerts
sudo touch $DATADIR/CA/index.txt
echo "01" > /tmp/serial; sudo mv /tmp/serial $DATADIR/CA
sudo chmod a+w /usr/share/geni-ch/CA/newcerts
sudo chmod a+w /usr/share/geni-ch/CA/private
sudo chmod a+w /usr/share/geni-ch/CA/serial
sudo chmod a+w /usr/share/geni-ch/CA


cp ../templates/services.ini.tmpl /tmp/services.ini

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
sudo ~/geni-ch/bin/geni-init-services /tmp/services.ini

# Set up trusted roots
sudo mkdir -p $DATADIR/portal/gcf.d/trusted_roots
cat $DATADIR/CA/cacert.pem $DATADIR/ma/ma-cert.pem > /tmp/CATedCACerts.pem
sudo mv /tmp/CATedCACerts.pem $DATADIR/portal/gcf.d/trusted_roots

# Set up database
PSQL="psql -U chtest -h localhost chtest"
for sch in cs logging ma pa sa sr
do
    $PSQL -f $CHAPIDIR/db/$sch/postgresql/schema.sql
done

for data in $CHAPIDIR/db/*/postgresql/data.sql
do
    $PSQL -f $data
done

cp ~/geni-ch/templates/install_service_registry.sql.tmpl /tmp/install_service_registry.sql
sed -i "s/@ch_host@/$HOSTNAME/g" /tmp/install_service_registry.sql
$PSQL < /tmp/install_service_registry.sql



# Set up chapi.ini
sudo cp ~/geni-ch/templates/chapi.ini.tmpl /etc/geni-chapi/chapi.ini
sudo sed -i "s/@pkgdatadir@/\/usr\/share\/geni-ch/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@pkgsysconfdir@/\/usr\/share\/geni-ch/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@ch_admin_email@/www-data@localhost/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@ch_authority@/$HOSTNAME/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_user@/chtest/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_pass@/chtest/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_host@/localhost/g" /etc/geni-chapi/chapi.ini
sudo sed -i "s/@db_name@/chtest/g" /etc/geni-chapi/chapi.ini

# Set up mail server
sudo yum install -y postfix # Use the local option
sudo postconf myhostname=`hostname -f`
sudo postconf mydomain=`hostname -d`
sudo postconf myorigin=\$mydomain
sudo postconf inet_protocols=ipv4
sudo postfix set-permissions
sudo rm /var/lib/postfix/master.lock
sudo service postfix restart

# Set up runtime
export PYTHONPATH=~/geni-tools/src:~/geni-ch

# Start test CH server
~/tools/test_server.py > /tmp/test_server.log &



