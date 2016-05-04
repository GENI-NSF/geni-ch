#----------------------------------------------------------------------
# Copyright (c) 2011-2016 Raytheon BBN Technologies
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

# Class to manage a set of ABAC credentials, certificates and prove queries

from ConfigParser import ConfigParser
import datetime
import optparse
import os
import subprocess
import sys
import tempfile
from chapi_log import *
from credential_tools import generate_credential
import xml.dom.minidom as minidom
from ABACKeyId import compute_keyid_from_cert_file, compute_keyid_from_cert

# Generate an ABACManager config file
# [Principals]
# name=certfile
# ...
# [Keys]
# name=keyfile
#
# Return name of config file and any tempfiles created in this process
def create_abac_manager_config_file(id_cert_files, id_certs, id_key_files, \
                                        raw_assertions):
    tempfiles = []
    # Format
    # [Principals]
    # The principals ("ME" and any in ID dictionary)
    # [Keys]
    # The keys ("ME")
    # [AssertionFiles]
    (fd, config_filename) = tempfile.mkstemp()
    tempfiles.append(config_filename)

    os.close(fd)
    file = open(config_filename, 'w')
    file.write('[Principals]\n')
    for id_name, id_cert_file in id_cert_files.items():
        file.write('%s=%s\n' % (id_name, id_cert_file))
    for id_name, id_cert in id_certs.items():
        (id_fd, id_filename) = tempfile.mkstemp()
        tempfiles.append(id_filename)
        os.close(id_fd)
        id_file = open(id_filename, 'w')
        id_file.write(id_cert)
        id_file.close()
        file.write('%s=%s\n' % (id_name, id_filename))

    file.write('[Keys]\n')
    for id_key_name, id_key_file in id_key_files.items():
        file.write('%s=%s\n' % (id_key_name, id_key_file))

    file.write('[AssertionFiles]\n')
    for raw_assertion in raw_assertions:
        (raw_fd, raw_filename) = tempfile.mkstemp()
        tempfiles.append(raw_filename)
        os.close(raw_fd)
        raw_file = open(raw_filename, 'w')
        raw_file.write(raw_assertion)
        raw_file.close()
        file.write('%s=None\n' % raw_filename)

    file.close()

    return config_filename, tempfiles

# Run a subprocess and grab and return contents of standard output
def grab_output_from_subprocess(args, include_stderr=False):
    if include_stderr:
        proc  = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    else:
        proc  = subprocess.Popen(args, stdout=subprocess.PIPE)

    result = ''
    chunk = proc.stdout.read()
    while chunk:
        result = result + chunk
        chunk = proc.stdout.read()
    return result

# Evaluate a query for given ID definitions and raw XML assertions
def execute_abac_query(query_expr, id_certs, raw_assertions = []):
    abac_manager = ABACManager(certs_by_name=id_certs, raw_assertions=raw_assertions)
    return abac_manager.query(query_expr)

# Get the key_id from a raw cert
def get_keyid_from_cert(cert, cert_file):
    return compute_keyid_from_cert(cert, cert_file)

# Get the key_id from a cert_file
def get_keyid_from_certfile(cert_file):
    return compute_keyid_from_cert_file(cert_file)

ABAC_TEMPLATE = "/usr/share/geni-chapi/abac_credential.xml.tmpl"


# Generate an ABAC credential of a given assertion signed by "ME"
# with a set of id_certs (a dictionary of {name : cert}
def generate_abac_credential(assertion, me_cert, me_key, 
                             id_certs = {}, id_cert_files = {}):
    template = open(ABAC_TEMPLATE).read()

    abac_manager = ABACManager(certs_by_name=id_certs, cert_files_by_name=id_cert_files)
    assertion_split = assertion.split('<-')

    subject_split = assertion_split[0].split('.')
    subject_name = subject_split[0]
    subject_role = subject_split[1]
    subject_keyid = abac_manager._ids_by_name[subject_name]

    target_split = assertion_split[1].split('.')
    target_name = target_split[0]
    target_keyid = abac_manager._ids_by_name[target_name]
    target_role = ''
    if len(target_split) > 1:
        target_role = "<role>%s</role>" % target_split[1]

    expires = datetime.datetime.utcnow() + datetime.timedelta(0, ABACManager.ten_years)

    abac_mapping = {
        '@expires@' : expires.isoformat(),
        '@subject_keyid@' : subject_keyid,
        '@subject_role@' : subject_role,
        '@target_keyid@' : target_keyid,
        '@target_role@' : target_role
        }

    signer_keyid = get_keyid_from_certfile(me_cert)
    if (signer_keyid != subject_keyid):
        print "Cannot create an ABAC credential where the subject is not the signer"
        sys.exit(0)

    return generate_credential(template, abac_mapping, me_cert, me_key)

# Assertions are a list of RT0 statements
#    X.Y<-Z
#    X.Y<-Z.W
# or RT1_lite statements (translated into RT0)
#    X.Y(S)<-Z(T)
#    X.Y(S)<-Z.W(T)

class ABACManager:

    # Constants
    ten_years = 10*365*24*3600

    # Constructor
    # Optional arguments:
    #    certs_by_name : A dictionary of principal_name => cert
    #    cert_files_by_name : A dictionary of principal_name => cert_filename
    #    key_files_by_name: A dictionary of principal_name => private_key_filename
    #    assertions :  A list of assertions as ABAC statements (X.Y<-Z e.g.)
    #    raw_assertions : A list of signed XML versions of ABAC statements
    #    assertion_files : A list of files contianing signed XML versions of ABAC statements
    #    options : List of command-line provided optional values
    def __init__(self, certs_by_name={}, cert_files_by_name={}, \
                     key_files_by_name={}, \
                     assertions=[], raw_assertions=[], assertion_files=[],  \
                     options=None):

        # For verbose debug output
        self._verbose = False

        # List of all ABAC principals (IDs) by name
        self._ids_by_name = {}

        # List of all files created from dumping certs or raw assertions
        self._created_filenames = []

        # All certs provided as raw cert objects
        self._certs = []

        # All cert files indexed by principal name
        self._cert_files = {}

        # All key files indexed by principal name
        self._key_files ={}

        # All raw assertions (as ABAC expressions)
        self._assertions = []

        # All assertion files
        self._assertion_files = []

        # Support internal prover
        # Maintain all assertions and links
        self._all_assertions = []
        self._all_links = {} # ABAC links : where can I get to from X (All Y st. Y<-X)

        # Process all the cert files
        for principal_name  in cert_files_by_name.keys():
            cert_file = cert_files_by_name[principal_name]
            principal = self.register_id(principal_name, cert_file)

        # Process all the raw certs
        for principal_name in certs_by_name.keys():
            cert = certs_by_name[principal_name]
            cert_file = self._dump_to_file(cert)
            principal = self.register_id_for_cert(principal_name, cert, cert_file)

        # Process the private keys
        for principal_name in key_files_by_name.keys():
            key_file = key_files_by_name[principal_name]
            self.register_key(principal_name,  key_file)

        # Process all assertions
        for assertion in assertions:
            self.register_assertion(assertion)

        # Process all raw_assertions
        for raw_assertion in raw_assertions:
            raw_assertion_file = self._dump_to_file(raw_assertion)
#            print "Loading raw assertion file " + raw_assertion_file
            self.register_assertion_file(raw_assertion_file)

        # Process all assertion files
        for assertion_file in assertion_files:
            self.register_assertion_file(assertion_file)


        # Save command-line options
        self._options = options

        # And process if provided
        if self._options:
            self.init_from_options()

    def init_from_options(self):

        # If a config file is provided, read it into the ABACManager
        if self._options.config:
            cp = ConfigParser()
            cp.optionxform=str
            cp.read(self._options.config)

            for name in cp.options('Principals'):
                cert_file = cp.get('Principals', name)
                self.register_id(name, cert_file)

            for name in cp.options('Keys'):
                key_file = cp.get('Keys', name)
                self.register_key(name, key_file)

            if 'Assertions' in cp.sections():
                for assertion in cp.options('Assertions'):
                    self.register_assertion(assertion)

            if 'AssertionFiles' in cp.sections():
                for assertion_file in cp.options("AssertionFiles"):
                    self.register_assertion_file(assertion_file)

        # Use all the other command-line options to override/augment
        # the values in the ABCManager

        # Add new principal ID's / keys
        if self._options.id:
            for id_filename in self._options.id:
                parts = id_filename.split(':')
                id_name = parts[0].strip()
                id_cert_file = None
                if len(parts) > 1:
                    id_cert_file = parts[1].strip()
                    self.register_id(id_name, id_cert_file)

                id_key_file = None
                if len(parts) > 2:
                    id_key_file = parts[2].strip()
                    self.register_key(name, id_key_file)

        # Register assertion files provided by command line
        if self._options.assertion_file:
            for assertion_file in self._options.assertion_file:
                self.register_assertion_file(assertion_file)

        # Grab pure ABAC assertions from commandline
        if self._options.assertion:
            for assertion in self._options.assertion:
                self.register_assertion(assertion)


    # Run command-line request for manager,
    # either querying or creating/writing an assertion credential
    def run(self):
        if self._options.query:
            ok, proof = self.query(self._options.query)
            if ok:
                print "Succeeded"
                print "\n".join(self.pretty_print_proof(proof))
            else:
                print "Failed"
        else:
            if not self._options.credential \
                    or not self._options.signer_cert  \
                    or not self._options.signer_key:
                print "Missing signer_cert or signer_key argument for creating credential"
            else:
                cred = generate_abac_credential(self._options.credential,
                                         self._options.signer_cert,
                                         self._options.signer_key,
                                         id_cert_files = self._cert_files)
                if self._options.outfile:
                    f = open(self._options.outfile, 'w')
                    f.write(cred)
                    f.close()
                else:
                    print cred

    # Traverse tree of ABAC expression finding path leading from 'from_expr' to 'to_expr'
    def find_path(self, from_expr, to_expr):
        if from_expr not in self._all_links:
            return False, None
        if to_expr in self._all_links[from_expr]:
            direct_link = "%s<-%s" % (to_expr, from_expr)
            return True, [direct_link]
        for link in self._all_links[from_expr]:
            found_sub_path, sub_proof = self.find_path(link, to_expr)
            if found_sub_path:
                direct_link = "%s<-%s" % (link, from_expr)
                return True, [direct_link] + sub_proof
        return False, None

    # Does given target have given role?
    # I.e. can we prove query statement Q (X.role<-target)
    # Return ok, proof
    def query(self, query_expression):

        # You gotta parse the expressions and go head-to-tail...
        parts = query_expression.split('<-')
        lhs = parts[0]
        # If we have a parameterized query e.g. A.B(C)<D, replace with A.B_C<-D
        if ')' in lhs and ')' in lhs:
            lhs = lhs.replace('(', '_')
            lhs = lhs.replace(')', '')
        rhs = parts[1]
        response, proof = self.find_path(rhs, lhs)
        return response, proof

    # Delete all the tempfiles create
    def __del__(self):
        for created_filename in self._created_filenames:
            os.remove(created_filename)

    # Register a new ID with the manager
    def register_id(self, name, cert_file):
        id = get_keyid_from_certfile(cert_file)
        self._ids_by_name[name] = id
        self._cert_files[name] = cert_file

    # Register a new ID with the manager for a raw_cert and cert_file
    def register_id_for_cert(self, name, cert, cert_file):
        id = get_keyid_from_cert(cert, cert_file)
        self._ids_by_name[name] = id
        self._cert_files[name] = cert_file

    # Load a private key with a principal
    def register_key(self, name, key_file):
        return # No longer needed without libabac context


    # Register a new assertion with the manager
    # Parse the expression and resolve the pieces
    # into RT1_line/RT0 roles and principal keyids
    # Generate exception if a principal is referenced but not registered
    def register_assertion(self, assertion):

        if self._verbose:
            chapi_audit_and_log('ABAC', "Registering assertion  " + assertion)

        # Grab assertion X.Y<-Z and store X.Y as subject_role, Z as principal
        self._all_assertions.append(assertion)
        parts = assertion.split('<-')
        subject_role= parts[0]
        principal = parts[1]
        if principal not in self._all_links:
            self._all_links[principal] = []
        self._all_links[principal].append(subject_role)


    def register_assertion_file(self, assertion_file):
        if self._verbose:
            chapi_audit_and_log('ABAC', "Registering assertion file " + assertion_file)

        if not self._validate_signed_document(assertion_file):
            print "Invalid assertion file: " + assertion_file
            return

        self._assertion_files.append(assertion_file)
        xml_doc = minidom.parse(assertion_file)
        head_node = xml_doc.getElementsByTagName('head')[0]
        head_keyid_elt = head_node.getElementsByTagName('keyid')[0]
        head_keyid = head_keyid_elt.childNodes[0].wholeText
        head_role_elt = head_node.getElementsByTagName('role')[0]
        head_role = head_role_elt.childNodes[0].wholeText

        tail_node = xml_doc.getElementsByTagName('tail')[0]
        tail_keyid_elt = tail_node.getElementsByTagName('keyid')[0]
        tail_keyid = tail_keyid_elt.childNodes[0].wholeText
        tail_role_elts = tail_node.getElementsByTagName('role')

        assertion = "%s.%s<-%s" % (head_keyid, head_role, tail_keyid)
        if len(tail_role_elts) > 0:
            tail_role = tail_role_elts[0].childNodes[0].wholeText
            assertion = "%s.%s<-%s.%s" % (head_keyid, head_role, tail_keyid, tail_role)

        assertion = self._transform_string(assertion)
        print "Asserting %s" % assertion
        self.register_assertion(assertion)

    def _validate_signed_document(self, assertion_file):
        args = ['xmlsec1', '--verify', assertion_file]
        output = grab_output_from_subprocess(args, True)
        return "FAIL" not in output

    # return list of user-readable credentials in proof chain
    def pretty_print_proof(self, proof):
        return proof

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

    # Dump an assertion to stdout or a file,
    # depending on whether outfile_name is set
    def _dump_assertion(self, assertion, outfile_name):
        outfile = sys.stdout
        if outfile_name:
            try:
                outfile = open(outfile_name, 'w')
            except Exception:
                print "Can't open outfile " + options.outfile
                sys.exit(-1)
        assertion.write(outfile)
        if outfile_name:
            outfile.close()


    # Lookup principal by name and return
    # Raise exception if not found
    def _resolve_principal(self, name):
        if self._ids_by_name.has_key(name):
            return self._ids_by_name[name]
        else:
            raise Exception("Unregistered principal: " + name)

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
            role_name = role_parts[0].strip()
            object_parts = role_parts[1].split(')')
            object_name = object_parts[0].strip()
            object = self._resolve_principal(object_name)
            return "%s_%s" % (role_name, object.keyid())
        else:
            raise Exception("Ill-formed role: " + role)

    # Replace keyids with string names in string
    def _transform_string(self, string):
        for id_name in self._ids_by_name.keys():
            id = self._ids_by_name[id_name]
            string = string.replace(id, id_name)
        return string


def main(argv=sys.argv):
    parser = optparse.OptionParser(description='Produce an ABAC Assertion')
    parser.add_option("--assertion",
                      help="ABAC-style assertion",
                      action = 'append',
                      default=[])
    parser.add_option("--assertion_file",
                      help="file containing ABAC assertion",
                      action = 'append',
                      default = [])
    parser.add_option("--signer_cert", help="File containing cred signer cert")
    parser.add_option("--signer_key", help="File containing cred signer key")
    parser.add_option("--id", action='append',
                      help="Identifier name (self-signed case) or " +
                      "name:cert_file (externally signed case")
    parser.add_option("--credential",
                      help="Expression of ABAC statement for which to generate signed credential")
    parser.add_option("--query", help="Query expression to evaluate")
    parser.add_option('--outfile',
                      help="name of file to put signed XML contents of credential (default=stdout)")
    parser.add_option('--config',
                      help="Name of config file with Principals/Keys/Assertions/AssertionFiles sections",
                      default = None)

    (options, args) = parser.parse_args(argv)

    # We need either a query or credential expression
    if not options.query and not options.credential:
        parser.print_help()
        sys.exit(-1)

    manager = ABACManager(options=options)
    manager._verbose = True
    manager.run()

if __name__ == "__main__":

    main()
    sys.exit(0)
