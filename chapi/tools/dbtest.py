from sqlalchemy import *
import sys

def main():
    db_url = "postgresql://portal:portal@marilac.gpolab.bbn.com/portal"
    db = create_engine(db_url)

    metadata = MetaData(db)

    services = Table('service_registry', metadata, autoload=True)

    for k in services.columns.keys():
        print str(k)

    import pdb; pdb.set_trace()
    
    stmt = services.query('service_urn', 'service_url')
    rs = stmt.execute()
    for row in rs:
        print row

if __name__ == "__main__":
    sys.exit(main())
