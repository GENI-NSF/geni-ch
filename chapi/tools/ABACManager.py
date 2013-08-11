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

# Class to manage a set o ABAC credentials, certificates and prove queries

import optparse
import os
import json
import sys
import tempfile
import ABAC

class ABACManager:

    # Constants
    ten_years = 10*365*24*3600

    # Certs and cert_files are dictioanries of name=> cert/cert_file
    # Assertions are a list of RT0 statements 
    #    X.Y<-Z 
    #    X.Y<-Z.W
    # or RT1_lite statements (translated into RT0)
    #    X.Y(S)<-Z(T)
    #    X.Y(S)<-Z.W(T)
    # 
    # Throw an exception if any assertion refers 
    #to any object not in a provided cert/file
    def __init__(self, my_name, my_cert_filename, my_key_filename, \
                     certs = {}, cert_files = {}, \
                     assertions = [], raw_assertions = [], \
                     assertion_files = []):
        self._my_name = my_name
        self._my_cert_filename = my_cert_filename
        self._my_key_filename = my_key_filename
        self._certs = certs
        self._cert_files = cert_files
        self._assertions = assertions
        self._assertion_files = assertion_files

        self._ids_by_name = {}
        self._files_by_name = {}

        # List of all files created from dumping certs or raw assertions
        self._created_filenames = []

        self._ctxt = ABAC.Context()

        # Register 'me' ID object (my name, cert, key) to the context
        self._me = ABAC.ID(self._my_cert_filename)
        self._me.load_privkey(self._my_key_filename)
        self.register_id(self._me, self._my_name)

        # dump all the certs into temp cert files and register
        for name in self._certs.keys():
            cert = self._certs[name]
            cert_filename = self._dump_to_file(cert)
            id = ABAC.ID(cert_filename)
            self.register_id(id, name)

        # Add all cert_files provided
        for name in self._cert_files.keys():
            cert_filename = self._cert_files[name]
            id = ABAC.ID(cert_filename)
            self.register_id(id, name)

        # Parse and create all the assertions. 
        for assertion in assertions:
            self.register_assertion(assertion)

        # Dump all raw_assertions (signed XML documents containing assertions)
        for raw_assertion in raw_assertions:
            raw_assertion_file = self._dump_to_file(raw_assertion)
#            print "Loading raw assertion file " + raw_assertion_file
            self._ctxt.load_attribute_file(raw_assertion_file)

        # Register assertions from files
        for assertion_file in assertion_files:
#            print "Loading assertion file " + assertion_file
            self._ctxt.load_attribute_file(assertion_file)

    # Does given target have given role?
    # I.e. can we prove ME.role<-target
    # Return ok, proof
    def query(self, target_name, role_name):
        role = self._resolve_role(role_name)
        target = self._resolve_principal(target_name)
        return self._ctxt.query(self._me.keyid() + "." + role, target.keyid())

    # Delete all the tempfiles create
    def __del__(self):
        for created_filename in self._created_filenames:
            os.remove(created_filename)

    # Register a new ID with the manager, loading into lookup table and context
    def register_id(self, id, name):
        if self._ids_by_name.has_key(name):
            raise Exception("ABACManager: name doubley defined " + name)
        self._ids_by_name[name] = id
#        print "Loading ID chunk " + name
        self._ctxt.load_id_chunk(id.cert_chunk())

    # Register a new assertion with the manager
    # Parse the expression and resolve the pieces 
    # into RT1_line/RT0 roles and principal keyids
    # Generate exception if a principal is referenced but not registered
    def register_assertion(self, assertion):
        assertion_pieces = assertion.split("<-")
        if len(assertion_pieces) != 2:
            raise Exception("Ill-formed assertion: need exactly 1 <- : " \
                                + assertion)
        lhs = assertion_pieces[0].strip()
        rhs = assertion_pieces[1].strip()
        lhs_pieces = lhs.split('.')
        if len(lhs_pieces) != 2:
            raise Exception("Ill-formed assertion LHS: need exactly 1 . : " \
                                + lhs)
        subject = self._resolve_principal(lhs_pieces[0])
        role = self._resolve_role(lhs_pieces[1])
        lhs_pieces = lhs.split('.')

        P = ABAC.Attribute(subject, role, self.ten_years)

        rhs_pieces = rhs.split('.')
        if len(rhs_pieces) >= 1:
            object = self._resolve_principal(rhs_pieces[0])

        if len(rhs_pieces) == 1:
            P.principal(object.keyid())
        elif len(rhs_pieces) == 2:
            role = self._resolve_role(rhs_pieces[1])
            P.role(object.keyid(), role)
        else:
            raise Exception("Ill-formed assertion RHS: need < 2 . : " + rhs)
        P.bake()
#        print "Loading assertion  chunk : " + str(P)
        self._ctxt.load_attribute_chunk(P.cert_chunk())

        return P


    # return list of user-readable credentials in proof chain
    def pretty_print_proof(self, proof):
        proof_texts = \
            ["%s<-%s" % \
                 (self._transform_string(elt.head().string()), \
                      self._transform_string(elt.tail().string())) \
                 for elt in proof]
        return proof_texts

    # Some internal helper functions


    # Dump a cert or credential to a file, returning filename
    def _dump_to_file(self, contents):
        (fd, filename) = tempfile.mkstemp()
        os.close(fd)
        file = open(filename, 'w')
        file.write(contents)
        file.close()
        self._created_filenames.append(filename)
        return filename

    # Lookup principal by name and return
    # Raise exception if not found
    def _resolve_principal(self, name):
        if self._ids_by_name.has_key(name):
            return self._ids_by_name[name]
        else:
            raise "Unregistered principal: " + name

    # Resolve a role string into RT1_lite syntax
    # I.e. 
    #    R => R (where R is a simple non-parenthesized string)
    #    R(S) => R_S.keyid() where S is the name of  principal
    def _resolve_role(self, role):
        has_lpar = role.find("(")
        has_rpar = role.find(")")
        if has_lpar < 0and has_rpar < 0:
            return role
        elif has_lpar >- 0 and has_rpar >= 0 and has_lpar < has_rpar:
            role_parts = role.split('(')
            role_name = role_parts[0]
            object_parts = role_parts[1].split(')')
            object_name = object_parts[0]
            object = self._resolve_principal(object_name)
            return "%s_%s" % (role_name, object.keyid())
        else:
            raise Exception("Ill-formed role: " + role)

    # Return the name for a cert
    def _lookup_cert(self, cert):
        for id_name in self._ids_by_name.keys():
            id_cert = self._ids_by_name[id_name]
            if (id_cert == cert):
                return id_name

    # Replace keyids with string names in string
    def _transform_string(self, string):
        for id_name in self._ids_by_name.keys():
            id = self._ids_by_name[id_name]
            id_keyid = id.keyid()
            string = string.replace(id_keyid, id_name)
        return string


def main():
    parser = optparse.OptionParser(description='Produce an ABAC Assertion')
    parser.add_option('--username', 
                      help="Name of user signing the assertion",
                      default="ME")
    parser.add_option('--user_cert_key', 
                      help="Cert/key for user signing the assertion")
    parser.add_option('--user_cert', 
                      help="Cert for user signing the assertion")
    parser.add_option('--user_key', 
                      help="Key for user signing the assertion")
    parser.add_option('--cert_files', 
                      help="JSON Dictionary of additional " + 
                      "user name/cert_filename pairs", 
                      default={})
    parser.add_option("--assertions", 
                      help="JSON list of ABAC-style assertions",
                      default=[])
    parser.add_option("--assertion_files", 
                      help="JSON list of files containing ABAC assertions",
                      default = [])
    parser.add_option("--target", 
                      help="Target (principal name) of ABAC query/assertion")
    parser.add_option("--role", 
                      help="Role  (ABAC style) of ABAC query/assertion")
    parser.add_option("--query", help="Generate a query (default = assertion)",
                      default=False, action="store_true")

    (options, args) = parser.parse_args(sys.argv)

    # We need either a user_cert and user_key OR a user_cert_key file
    # We need both target and role for query or assertion
    if (not options.user_cert_key and \
            (not options.user_cert or not options.user_key)) or \
            (not options.target or not options.role):
        parser.print_help()
        sys.exit(-1)

    # ABAC wants simple strings not unicode (which JSON provides)

    # Translate cert_files structure from JSON to python
    cert_files_unicode = json.loads(options.cert_files)
    cert_files = {}
    for id_name_unicode in cert_files_unicode.keys():
        id_name = str(id_name_unicode)
        cert_file_unicode = cert_files_unicode[id_name_unicode]
        cert_file = str(cert_file_unicode)
        cert_files[id_name] = cert_file

    # Translate assertion_files structure from JSON to python
    assertion_files = []
    if options.assertion_files != []:
        assertion_files = \
            [str(a_file) for a_file in json.loads(options.assertion_files)]

    # Translate assertions from JSON to python
    assertions = []
    if options.assertions != []:
        assertions = \
            [str(assertion) for assertion in json.loads(options.assertions)]

    user_cert = options.user_cert
    user_key = options.user_key
    if options.user_cert_key:
        user_cert = options.user_cert_key
        user_key = options.user_cert_key

    manager = ABACManager(options.username, user_cert, user_key, \
                              assertion_files = assertion_files, \
                              assertions = assertions, \
                              cert_files=cert_files)

    if options.query:
        # Generate and prove a query
        ok, proof = manager.query(options.target, options.role)
        if ok:
            print "\n".join(manager.pretty_print_proof(proof))
        else:
            print "Failed"
    elif options.target and options.role:
        # Generate an assertion
        assertion_text = "%s.%s<-%s" % \
            ( options.username, options.role, options.target)
        assertion = manager.register_assertion(assertion_text)
        assertion.write(sys.stdout)

if __name__ == "__main__":

    main()
    sys.exit(0)




    
                          


    
