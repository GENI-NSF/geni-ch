import amsoil.core.pluginmanager as pm
from sqlalchemy import *
from sqlalchemy.orm import sessionmaker

# Simple class to hold the basis of DB queries against GPO CH Database
# Loads the database table schemas
class CHDatabaseEngine:

    def __init__(self):
        config = pm.getService('config')
        self.db_url = config.get('chrm.db_url')
        self.db = create_engine(self.db_url)
        self.session_class = sessionmaker(bind=self.db)
        self.metadata = MetaData(self.db)

        self.SLICE_TABLE = Table('sa_slice', self.metadata, autoload=True)
        self.SLICE_MEMBER_TABLE = \
            Table('sa_slice_member', self.metadata, autoload=True)
        self.PROJECT_TABLE = Table('pa_project', self.metadata, autoload=True)
        self.PROJECT_MEMBER_TABLE = \
            Table('pa_project_member', self.metadata, autoload=True)
        self.MEMBER_ATTRIBUTE_TABLE = \
            Table('ma_member_attribute', self.metadata, autoload=True)
        self.ASSERTION_TABLE = Table('cs_assertion', self.metadata, autoload=True)
        self.ROLE_TABLE = Table('cs_attribute', self.metadata, autoload=True)

    def getSession(self):
        return self.session_class()


