from sqlalchemy import *
from sqlalchemy.orm import sessionmaker
import sys

def services_test(db):
    metadata = MetaData(db)
    services = Table('service_registry', metadata, autoload=True)

    for k in services.columns.keys():
        print str(k)

    import pdb; pdb.set_trace()
    
    stmt = services.query('service_urn', 'service_url')
    rs = stmt.execute()
    for row in rs:
        print row

def slice_test(db):
    metadata = MetaData(db)
    session_class = sessionmaker(bind=db)
    SLICE_TABLE = Table('sa_slice', metadata, autoload=True)
    PROJECT_TABLE = Table('pa_project', metadata, autoload=True)

    urn = 'urn:publicid:IDN+ch-mb.gpolab.bbn.com:PROJ1+slice+SLICE1'

    member_urn = "urn:publicid:IDN+ch-mb.gpolab.bbn.com+user+mbrinn"

    session = session_class()
    q = session.query(SLICE_TABLE, PROJECT_TABLE)
    q = q.filter(SLICE_TABLE.c.project_id == PROJECT_TABLE.c.project_id)
    q = q.filter(SLICE_TABLE.c.slice_urn == urn)
    rows = q.all()
    session.close()
    for row in rows: 
        print "ROW = " + str(row.slice_urn) + " " + \
            str(row.project_id)  + " " + str(row.expiration) + " " + \
            str(row.project_name) + " " + \
            to_project_urn(row.project_name) + " " + \
            from_project_urn(to_project_urn(row.project_name))

def from_project_urn(project_urn):
    parts = project_urn.split('+')
    return parts[len(parts)-1]

def to_project_urn(project_name):
    return "urn:publicid:IDN+ch-mb.gpolab.bbn.com+project+%s" % project_name


def main():
    db_url_filename = "/tmp/chrm_db_url.txt"
    db_url = open(db_url_filename).read()
    db = create_engine(db_url)

#    services_test(db)
    slice_test(db)

if __name__ == "__main__":
    sys.exit(main())
