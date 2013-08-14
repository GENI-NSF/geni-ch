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

import amsoil.core.log
import amsoil.core.pluginmanager as pm
from amsoil.core import serviceinterface
from chapi.DelegateBase import DelegateBase
from chapi.HandlerBase import HandlerBase
from chapi.Exceptions import *

pgch_logger = amsoil.core.log.getLogger('pgchv1')

class PGCHv1Handler(HandlerBase):

    def __init__(self):
        super(PGCHv1Handler, self).__init__(pgch_logger)

    def GetVersion(self):
        try:
            return self._delegate.GetVersion()
        except Exception as e:
            return self._errorReturn(e)


    def GetCredential(self, args=None):
        try:
            return self._delegate.GetCredential(args)
        except Exception as e:
            return self._errorReturn(e)

    def Resolve(self, args):
        try:
            return self._delegate.Resolve(args)
        except Exception as e:
            return self._errorReturn(e)

    def Register(self, args):
        try:
            return self._delegate.Register(args)
        except Exception as e:
            return self._errorReturn(e)


    def RenewSlice(self, args):
        try:
            return self._delegate.RenewSlice(args)
        except Exception as e:
            return self._errorReturn(e)

    def GetKeys(self, args):
        try:
            return self._delegate.GetKeys(args)
        except Exception as e:
            return self._errorReturn(e)

    def ListComponents(self, args):
        try:
            return self._delegate.ListComponents(args)
        except Exception as e:
            return self._errorReturn(e)

class PGCHv1Delegate(DelegateBase):

    def __init__(self):
        super(PGCHv1Delegate, self).__init__(pgch_logger)

    def GetVersion(self):
        # Note that the SA GetVersion is not implemented
        # return value should be a struct with a bunch of entries
        return self._successReturn("GetVersion")

    def GetCredential(self, args=None):
        # all none means return user cred
        # else cred is user cred, id is uuid or urn of object, type=Slice
        #    where omni always uses the urn
        # return is slice credential
        #args: credential, type, uuid, urn
        return self._successReturn("GetCredential" + str(args))

    def Resolve(self, args):
        # Omni uses this, Flack may not need it

        # ID may be a uuid, hrn, or urn
        #   Omni uses hrn for type=User, urn for type=Slice
        # type is Slice or User
        # args: credential, hrn, urn, uuid, type
        # Return is dict:
#When the type is Slice:
#
#{
#  "urn"  : "URN of the slice",
#  "uuid" : "rfc4122 universally unique identifier",
#  "creator_uuid" : "UUID of the user who created the slice",
#  "creator_urn" : "URN of the user who created the slice",
#  "gid"  : "ProtoGENI Identifier (an x509 certificate)",
#  "component_managers" : "List of CM URNs which are known to contain slivers or tickets in this slice. May be stale"
#}
#When the type is User:
#
#{
#  "uid"  : "login (Emulab) ID of the user.",
#  "hrn"  : "Human Readable Name (HRN)",
#  "uuid" : "rfc4122 universally unique identifier",
#  "email": "registered email address",
#  "gid"  : "ProtoGENI Identifier (an x509 certificate)",
#  "name" : "common name",
#}
        return self._successReturn("Resolve" + str(args))

    def Register(self, args):
        # Omni uses this, Flack should not for our purposes
        # args are credential, hrn, urn, type
        # cred is user cred, type must be Slice
        # returns slice cred
        return self._successReturn("Register"  + str(args))

    def RenewSlice(self, args):
        # Omni uses this, Flack should not for our purposes
        # args are credential, hrn, urn, type
        # cred is user cred, type must be Slice
        # returns slice cred
        return self._successReturn("RenewSlice" + str(args))

    def GetKeys(self, args):
        # cred is user cred
        # return list( of dict(type='ssh', key=$key))
        # args: credential
        return self._successReturn("GetKeys" + str(args))


    def ListComponents(self, args):
        # Returns list of CMs (AMs)
        # cred is user cred or slice cred - Omni uses user cred
        # return list( of dict(gid=<cert>, hrn=<hrn>, url=<AM URL>))
        # Matt seems to say hrn is not critical, and can maybe even skip cert
        # args: credential
        return self._successReturn("ListComponents" + str(args))

