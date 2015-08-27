#!/bin/bash
# Moved expired data from logging_entry to logging_entry_old
# Moved associated data from logging_entry_attribute to logging_entry_attribute_old
#
# Usage: archive_sa_entry_table.sh expired_time

if [ $# -ne 1 ]; then
    echo "Usage: archive_sa_entry_tables.sh time (ex. '2014-03-10')"
    exit
else
    EXPIRED_TIME=$1
    echo "BEGIN;" > /tmp/slice_tables_mod.sql
    echo "insert into sa_slice_member_old (select * from sa_slice_member where slice_id in (select slice_id from sa_slice where expiration < '$EXPIRED_TIME')); " >> /tmp/slice_tables_mod.sql
    echo "insert into sa_slice_old (select * from sa_slice where expiration < '$EXPIRED_TIME'); " >> /tmp/slice_tables_mod.sql
    echo "delete from sa_slice_member where slice_id in (select slice_id from sa_slice where expiration < '$EXPIRED_TIME'); " >> /tmp/slice_tables_mod.sql
    echo "delete from sa_slice where expiration < '$EXPIRED_TIME'; " >> /tmp/slice_tables_mod.sql
    echo "COMMIT;" >> /tmp/slice_tables_mod.sql
    psql -U portal -h localhost portal -f /tmp/slice_tables_mod.sql
fi
