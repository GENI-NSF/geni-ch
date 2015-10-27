# Install geni-ch
export URL_BASE='http://www.gpolab.bbn.com/experiment-support/gposw'
sudo curl "${URL_BASE}"/centos/geni.repo -o /etc/yum.repos.d/geni.repo
sudo yum install -y --nogpg geni-chapi

------

# Install postgresql server
 

sudo yum -y install postgresql-server

sudo postgresql-setup initdb
sudo systemctl enable postgresql.service
sudo systemctl start postgresql.service

POSTGRESQL_DIR=/var/lib/pgsql/data
DB_HOST=localhost
DB_USER=portal
DB_DATABASE=portal
DB_ADMIN_PASSWORD=postgres
DB_PASSWORD=portal

sudo -u postgres /usr/bin/psql \
    -c "alter user postgres with password '$DB_ADMIN_PASSWORD'"

sudo sed -i -e "\$alisten_addresses='*'" $POSTGRESQL_DIR/postgresql.conf
sudo sed -i -e "s/^host/#host/g" $POSTGRESQL_DIR/pg_hba.conf
sudo sed -i -e "\$ahost all all 0.0.0.0/0 md5" $POSTGRESQL_DIR/pg_hba.conf
sudo sed -i -e "\$ahost all all ::1/128 md5" $POSTGRESQL_DIR/pg_hba.conf

sudo systemctl restart postgresql.service

sudo -u postgres createuser -S -D -R $DB_USER
sudo -u postgres psql -c "alter user $DB_USER with password '$DB_PASSWORD'"
sudo -u postgres createdb $DB_DATABASE
echo "$DB_HOST:*:$DB_DATABASE:$DB_USER:$DB_PASSWORD"  > ~/.pgpass
chmod 0600 ~/.pgpass
touch ~/.psql_history
PSQL="psql -U $DB_USER -h $DB_HOST $DB_DATABASE"


# Then follow all the instuctions for putting CH tables and entries into DB
