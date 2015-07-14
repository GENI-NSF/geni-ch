
To create a database and a user in PostgreSQL:

CREATE USER svcreg WITH PASSWORD 'svcreg';

CREATE DATABASE genisr;

GRANT ALL PRIVILEGES ON DATABASE genisr to svcreg;


# Login as credstore attached to database genica
psql -d genisr -U svcreg -h localhost
