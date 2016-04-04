import os
import threading
# Maintain mapping of client (caller) certs by thread_id
class ClientCertRegistry(object):
    _CERTS_BY_THREAD_ID = {}

def register_client_cert(cert):
    tid = threading.current_thread().ident
    ClientCertRegistry._CERTS_BY_THREAD_ID[tid] = cert
#    print "REGISTERING %s %s %s %s" % \
#        (os.getpid(), tid, cert, ClientCertRegistry._CERTS_BY_THREAD_ID)

def lookup_client_cert():
    tid = threading.current_thread().ident
#    print "LOOKING_UP %s %s %s" % \
#        (os.getpid(), tid, ClientCertRegistry._CERTS_BY_THREAD_ID)
    if tid in ClientCertRegistry._CERTS_BY_THREAD_ID:
        return ClientCertRegistry._CERTS_BY_THREAD_ID[tid]
    else:
        return None
