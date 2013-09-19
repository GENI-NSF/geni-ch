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

import sfa.trust.certificate
import subprocess
import os
import tempfile

# A set of utilities to pull infomration out of X509 certs

# Pull the certificate from the speaks-for credential
def get_cert_from_credential(cred):
    start_tag = '<X509Certificate>'
    end_tag = '</X509Certificate>'
    start_index = cred.find(start_tag)
    end_index = cred.find(end_tag)
    raw_cert = cred[start_index+len(start_tag):end_index]
    cert_string = '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----' % raw_cert
    return cert_string

# Pull out the UUID from the certificate
def get_uuid_from_cert(cert):
    cert_object = sfa.trust.certificate.Certificate(string=cert)
    subject_alt_names = cert_object.get_extension('subjectAltName')
    san_parts = subject_alt_names.split(',')
    uuid = None
    for san_part in san_parts:
        san_part = san_part.strip()
        if san_part.startswith('URI:urn:uuid'):
            uuid = san_part[13:]
            break
    return uuid

# Pull out the URN from the certificate
def get_urn_from_cert(cert):
    cert_object = sfa.trust.certificate.Certificate(string=cert)
    subject_alt_names = cert_object.get_extension('subjectAltName')
    san_parts = subject_alt_names.split(',')
    urn = None
    for san_part in san_parts:
        san_part = san_part.strip()
        if san_part.startswith('URI:urn:publicid'):
            urn = san_part[4:]
            break
    return urn

# Pull the object name fro the URN
# It is the part after the last +
def get_name_from_urn(urn):
    parts = urn.split("+")
    return str(parts[len(parts)-1])

# Retrieve project_name, authority, slice_name from slice urn
def extract_data_from_slice_urn(urn):
    # Pull out slice name and project_name
    urn_parts = urn.split('+')
    slice_name = urn_paorts[len(urn_parts)-1]
    authority = urn_parts[1]
    authority_parts = authority.split(':')
    if len(authority_parts) != 2:
        raise Exception("No project specified in slice urn: " + urn)
    authority = authority_parts[0]
    project_name = authority_parts[1]
    return project_name, authority, slice_name

# Generate a CSR, return private key and file containing csr
def make_csr():
    (csr_fd, csr_file) = tempfile.mkstemp()
    os.close(csr_fd)
    (key_fd, key_file) = tempfile.mkstemp()
    os.close(key_fd)
    csr_request_args = ['/usr/bin/openssl', 'req', '-new', \
                            '-newkey', 'rsa:1024', \
                            '-nodes', \
                            '-keyout', key_file, \
                            '-out', csr_file, '-batch']
    subprocess.call(csr_request_args)
    private_key = open(key_file).read()
    return private_key, csr_file

# Generate an X509 cert and private key
# Return cert
def make_cert(uuid, email, urn, \
                          signer_cert_file, signer_key_file, csr_file):

    # sign the csr to create cert
    extname = 'v3_user'
    extdata_template = "[ %s ]\n" + \
        "subjectKeyIdentifier=hash\n" + \
        "authorityKeyIdentifier=keyid:always,issuer:always\n" + \
        "basicConstraints = CA:false\n"
    extdata = extdata_template % extname
        
    if email:
        extdata = extdata + \
            "subjectAltName=email:copy,URI:%s,URI:urn:uuid:%s\n" \
            % (urn, uuid);
        subject = "/CN=%s/emailAddress=%s" % (uuid, email)
    else:
        extdata = extdata + \
            "subjectAltName=URI:%s,URI:urn:uuid:%s\n" % (urn, uuid)
        subject = "/CN=%s" % uuid;

    (ext_fd, ext_file) = tempfile.mkstemp()
    os.close(ext_fd)
    open(ext_file, 'w').write(extdata)

    (cert_fd, cert_file) = tempfile.mkstemp()
    os.close(cert_fd)

    sign_csr_args = ['/usr/bin/openssl', 'ca', \
                         '-config', '/usr/share/geni-ch/CA/openssl.cnf', \
                         '-extfile', ext_file, \
                         '-policy', 'policy_anything', \
                         '-out', cert_file, \
                         '-in', csr_file, \
                         '-extensions', extname, \
                         '-batch', \
                         '-notext', \
                         '-cert', signer_cert_file,\
                         '-keyfile', signer_key_file, \
                         '-subj', subject ]
    print " ".join(sign_csr_args)
#    os.system(" ".join(sign_csr_args))

        # Grab cert from cert_file
    cert_pem = open(cert_file).read()
#        print "CERT_PEM = " + cert_pem

    return cert_pem

