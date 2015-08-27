#!/bin/bash
# Moved expired data from logging_entry to logging_entry_old
# Moved associated data from logging_entry_attribute to logging_entry_attribute_old
#
# Usage: archive_log_entry_table.sh expired_time

if [ $# -ne 1 ]; then
    echo "Usage: archive_log_entry_tables.sh time (ex. '2014-03-10')"
    exit
else
   
    EXPIRED_TIME=$1
    echo "BEGIN;" > /tmp/log_entry_mod.sql
    echo "insert into logging_entry_old (select * from logging_entry where event_time < '$EXPIRED_TIME');" >> /tmp/log_entry_mod.sql
    echo "insert into logging_entry_attribute_old select * from logging_entry_attribute where event_id in (select id from logging_entry where event_time < '$EXPIRED_TIME');" >> /tmp/log_entry_mod.sql
    echo "delete from logging_entry_attribute where event_id in (select id from logging_entry where event_time < '$EXPIRED_TIME');" >> /tmp/log_entry_mod.sql
    echo "delete from logging_entry where event_time < '$EXPIRED_TIME';" >> /tmp/log_entry_mod.sql
    echo "COMMIT;" >> /tmp/log_entry_mod.sql
    psql -U portal -h localhost portal -f /tmp/log_entry_mod.sql
fi
