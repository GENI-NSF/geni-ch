#----------------------------------------------------------------------
# Copyright (c) 2011-2013 Raytheon BBN Technologies
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and/or hardware specification (the "Work") to
# deal in the Work without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Work, and to permit persons to whom the Work
# is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Work.
#
# THE WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS
# IN THE WORK.
#----------------------------------------------------------------------

import sys, os
from sqlalchemy import *
from sqlalchemy.orm import sessionmaker
import optparse

# Test program for reading/writing the sqllite config database file
# Currently doesn't work: use admin/client.py instead

def parseOptions():
    parser = optparse.OptionParser()
    
    default_config_db_url = \
        "sqlite:///%s/AMsoil/deploy/config.db" % os.getenv('HOME')
    parser.add_option("--db_url", help="URL of confg database",
                      default=default_config_db_url)
    parser.add_option("--dump", help="Dump current config DB", \
                          action="store_true", default=False)
    parser.add_option("--update", \
                          help="Whether to update existing database record", \
                          action="store_true", default=False)
    parser.add_option("--key", help="Name of key to set value", \
                          default=None)
    parser.add_option("--value", help="Name of value to set for key", \
                          default=None)
    return parser.parse_args(sys.argv)


def main():

    opts, args = parseOptions()
    config_db = create_engine(opts.db_url)
    session_class = sessionmaker(bind=config_db)
    metadata = MetaData(config_db)

    CONFIG_TABLE = Table('config', metadata, autoload=True)
    session = session_class()

    if opts.dump:
        q = session.query(CONFIG_TABLE)
        rows = q.all()
        for row in rows:
            import pdb;pdb.set_trace()
            print str(row.key) + ": " + str(row.value)

    if opts.key and opts.value:
        if opts.update:
            sql = "update config set value = '%s' where key = '%s'" % \
                (opts.value, opts.value )
            session.execute(sql)
            session.commit()
        elif opts.delete:
            # Delete existing record
            sql = "delete from config where key = '%s'" % opts.key
            session.execute(sql)
            session.commit()
        else:
            # Insert new record
            sql = "insert into config (key, value) values ('%s', '%s')" % \
                (opts.key, opts.value)
            session.execute(sql)
            session.commit()
    
    session.close()
    

if __name__ == "__main__":
    sys.exit(main())
    
