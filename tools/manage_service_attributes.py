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

# A tool to add/remove attributes to service entries
# Check that the name and value are valid as defined in the 
# CH_constants.defined_attfibutes

import CH_constants as CH
import optparse
import subprocess
import sys
from ABACManager import grab_output_from_subprocess

CMD_PREFIX = ['psql', '-h', 'localhost', '-U', 'portal', '-t', '-c']


def main():
    parser = optparse.OptionParser()
    parser.add_option("--url", help="URL of service", default=None)
    parser.add_option("--urn", help="URN of service", default=None)
    parser.add_option("--uid", help="ID of service", default = None)
    parser.add_option("--name", help="Name of attribute", default=None)
    parser.add_option("--value", help="Value of attribute", default=None)
    parser.add_option("--remove", help="Whether to remove attribute", \
                          action="store_true", dest="remove")
    opts, args = parser.parse_args(sys.argv)

    if not opts.url and not opts.urn and not opts.uid:
        print "URL or URN or UID must be specified"
        return

    if not opts.name or not opts.value:
        print "Attribute name and value must be specified"
        return

    if opts.remove:
        remove_service_attribute(opts)
    else:
        add_service_attribute(opts)

def add_service_attribute(opts):
    service_id, service_type = extract_identifier(opts)
    if not service_id:
        return
    if not validate_name_value(opts.name, opts.value, service_type):
        print "Invalid name/value pair for service attribute: %s %s" % \
            (opts.name, opts.value)
        return
    sql = "insert into service_registry_attribute (service_id, name, value) "+\
        " values (%d, '%s', '%s')" % (service_id, opts.name, opts.value)
    print "add_service_attribute: %s " % sql
    cmd = CMD_PREFIX + [sql]
    output = grab_output_from_subprocess(cmd)

def remove_service_attribute(opts):
    print "Remove_record %s " % opts
    service_id, service_type = extract_identifier(opts)
    if not service_id:
        return
    sql = "delete from service_registry_attribute where " + \
        "service_id = %d and name = '%s' and value = '%s'" % \
        (service_id, opts.name, opts.value)
    print "remove_service_attribute: %s" % sql
    cmd = CMD_PREFIX + [sql]
    output = grab_output_from_subprocess(cmd)

# Return service identifier by matching URL or URN to given service
# Or return the givne ID if exists
def extract_identifier(opts):
    prefix = "select id, service_type from service_registry where "
    if opts.uid:
        sql = prefix + ("id = '%s'" % opts.uid)
    elif opts.urn:
        sql = prefix + ("service_urn = '%s'" % opts.urn)
    elif opts.url:
        sql = prefix + ("service_url = '%s'" % opts.url)
    else:
        print "None of UID, URN or URL defined"
        return None, None

    cmd = ['psql', '-U', 'portal', '-h', 'localhost', '-t', '-c', sql]
    output = grab_output_from_subprocess(cmd)
    lines = output.strip().split('\n')
    if len(lines) != 1 or len(lines[0]) == 0:
        print "Can't find unique value for query %s" % sql
        return None, None
    uid, type = lines[0].split('|')
    uid = int(uid.strip())
    type = int(type.strip())
    return uid, type

def validate_name_value(name, value, service_type):
    if name not in CH.defined_attributes:
        print "Attribute name %s not defined" % name
        return False
    if 'acceptable_values' in CH.defined_attributes[name] and \
            value not in CH.defined_attributes[name]['acceptable_values']:
        print" Attribute value %s not allowed for attribute name %s" % \
            (name, value)
        return False
    if 'service_types' in CH.defined_attributes[name] and \
            service_type not in CH.defined_attributes[name]['service_types']:
        print "Service type %d not allowed for attribute %s" % \
            (service_type, name)
        return False
    return True


if __name__ == "__main__":
    sys.exit(main())

