# ----------------------------------------------------------------------
# Copyright (c) 2016 Raytheon BBN Technologies
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
# ----------------------------------------------------------------------

# Module containing routines for generating credentials of different
# kinds by instantiating templates

import json
import os
import subprocess
import sys
import tempfile
import xml.dom.minidom as minidom


# Main: python credential_tools.py template_file mapping_file signer_cert signer_key output_filename=None
def main(args):
    if len(args) < 5:
        print "Usage: credential_tools.py template_file mapping_file signer_cert signer_key output_file=None"
        sys.exit(0)

    template_file = args[1]
    mapping_file = args[2]
    signer_cert = args[3]
    signer_key = args[4]
    output_file = None
    if len(args) > 5:
        output_file = args[5]

    template = open(template_file).read()
    mapping = json.loads(open(mapping_file).read())

    cred = generate_credential(template, mapping, signer_cert, signer_key)
    if output_file:
        out = open(output_file, 'w')
        out.write(cred)
        out.close()
    else:
        print cred


# Generate a credential by substituting all entries in mapping
# Then signing the credential and returning the resultant XML
def generate_credential(template, mapping, signer_cert, signer_key):

    # Replace all keys with value from mapping in template
    for key, value in mapping.items():
        template = template.replace(key, value)

    unsigned_cred_file = tempfile.NamedTemporaryFile(delete=False)
    unsigned_cred_file.write(template)
    unsigned_cred_file.close()

    CERT_END = '-----END CERTIFICATE-----\n'

    signer_cert_contents = open(signer_cert).read()
    cert_chain = signer_cert_contents.split(CERT_END)
    cert_filenames = []
    for cert_element in cert_chain:
        if not cert_element == 0:
            continue
        cert_file = tempfile.NamedTemporaryFile(delete=False)
        cert_filenames.append(cert_file.name)
        cert_file.write(cert_element + CERT_END)
        cert_file.close()

    # Pull ref id from credential tag of credential template to be signed
    template_doc = minidom.parseString(template)
    credential_elts = template_doc.getElementsByTagName('credential')
    if not credential_elts or not credential_elts[0].getAttribute('xml:id'):
        print "Template doesn't contain credential element with xml:id attribute"
        return None

    refid = credential_elts[0].getAttribute('xml:id')
    args = ['xmlsec1', '--sign', '--node-id', refid, '--privkey-pem',
            "%s,%s" % (signer_key, ",".join(cert_filenames)),
            unsigned_cred_file.name]
    ucred_xml = subprocess.check_output(args)

    # Delete temp files
    for cert_filename in cert_filenames:
        os.unlink(cert_filename)
    os.unlink(unsigned_cred_file.name)

    return ucred_xml


if __name__ == "__main__":
    main(sys.argv)
