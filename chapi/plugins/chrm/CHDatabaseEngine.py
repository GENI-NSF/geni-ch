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

import amsoil.core.pluginmanager as pm
from sqlalchemy import *
from sqlalchemy.orm import sessionmaker

# Simple class to hold the basis of DB queries against GPO CH Database
# Loads the database table schemas
class CHDatabaseEngine:

    # Grab a database engine and pre-fetch table meta-data for all
    # Tables we'll be using
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
        self.MEMBER_TABLE = \
            Table('ma_member', self.metadata, autoload=True)
        self.MEMBER_ATTRIBUTE_TABLE = \
            Table('ma_member_attribute', self.metadata, autoload=True)
        self.SSH_KEY_TABLE = \
            Table('ma_ssh_key', self.metadata, autoload=True)
        self.OUTSIDE_CERT_TABLE = \
            Table('ma_outside_cert', self.metadata, autoload=True)
        self.ASSERTION_TABLE = Table('cs_assertion', self.metadata, autoload=True)
        self.SERVICES_TABLE = \
            Table('service_registry', self.metadata, autoload=True)
        self.ROLE_TABLE = Table('cs_attribute', self.metadata, autoload=True)

    # Get a new session on the database engine
    def getSession(self):
        return self.session_class()


