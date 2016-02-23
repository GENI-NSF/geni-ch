#----------------------------------------------------------------------
# Copyright (c) 2013-2016 Raytheon BBN Technologies
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
import os, os.path, sys
import json
import optparse
import random
import subprocess
import tempfile
import time

class ScalingTester:
    def __init__(self, url, object_file, user_file, 
                 match_field, filter_fields, method, client_location):
        self._url = url
        self._method = method
        self._object_file = object_file
        self._user_file = user_file
        self._match_field = match_field
        self._filter_fields = self._parseFilterFields(filter_fields)
        self._client_location = client_location
        self._object_ids = self._parseObjectIDs()
        self._options_file = self._generateOptionsFile()
        self._users = self._parseUsers()

    def _parseObjectIDs(self): 
        ids_raw = open(self._object_file).read()
        ids = ids_raw.split('\n')
        return [id.strip() for id in ids if len(id.strip()) > 0]

    def _parseUsers(self): 
        users_raw = open(self._user_file).read()
        return json.loads(users_raw)
    
    def _parseFilterFields(self, filter_fields):
        if not filter_fields: return None
        return [ff.strip() for ff in filter_fields.split(',')]

    # Make an options file for querying all objects by ID by field
    def _generateOptionsFile(self): 
        (fd, filename) = tempfile.mkstemp()
        os.close(fd)
        options = {'match' : {self._match_field : self._object_ids}}
        if self._filter_fields:
            options['filter'] = self._filter_fields
        options_data = json.dumps(options)
        open(filename, 'w').write(options_data)
        return filename

    def invoke(self, num_concurrent):
        (fd, script_filename) = tempfile.mkstemp()
        os.close(fd)
        script_file = open(script_filename, 'w')
        for i in range(num_concurrent):
            user_index = random.randint(0, len(self._users)-1)
            user_cert = self._users[user_index]['cert']
            user_key = self._users[user_index]['key']
#            print "CERT = %s KEY = %s" % (user_cert, user_key)
        
            command_template = "time (python %s --key %s --cert %s " + \
                "--options_file %s --method %s --url %s 2&>1 > /dev/null) &\n"
            command =  command_template % \
                (self._client_location, user_key, user_cert, \
                     self._options_file, self._method, self._url)
            script_file.write(command)

        script_file.close()
#        print "SC = " + script_filename
        output = self.run_script(script_filename)
        real_timing_raw = \
            [line for line in output.split('\n') if line.startswith('real')]
        real_timing = [rt.split('\t')[1] for rt in real_timing_raw]
        secs = [self.parseTime(rt) for rt in real_timing]
        mean = 0; 
        for sec in secs: mean = mean + sec
        mean = mean / num_concurrent
        print "Mean  %s : %s" % (mean, secs) 

    def run_script(self, script_filename):
        run_script_command = ["/bin/bash", script_filename]
        proc = subprocess.Popen(run_script_command, stderr=subprocess.PIPE)

        result = ''
        chunk = proc.stderr.read()
        while chunk:
            result = result + chunk
            chunk = proc.stderr.read()
        return result

    def parseTime(self, time_min_sec):
        parts = time_min_sec.split('m')
        min = int(parts[0]) 
        sec = float(parts[1].split('s')[0])
        sec = 60*min + sec
        return sec

def parseOptions(args):
    parser = optparse.OptionParser()
    parser.add_option("--url", help="URL of service to which to connect",
                      default=None)
    parser.add_option("--object_file", 
                      help="File containing list of object IDs", 
                      default=None)
    parser.add_option("--user_file", 
                      help="JSON File containing list {cert, key} dicts",
                      default=None)
    parser.add_option("--method", 
                      help="Name of method to invoke",
                      default='lookup_slices')
    parser.add_option("--match_field", help="Name of object field to match", 
                      default="SLICE_UID")
    parser.add_option("--filter_fields", help="List of object fields to select",
                      default=None)
    parser.add_option("--client_location", help="Location of client.py",
                      default = "client.py")
    parser.add_option("--num_concurrent", 
                      help="Number concurrent calls", default=1)
    parser.add_option("--frequency", help='Time to wait between invocations',
                      default=5)
    parser.add_option("--num_iterations", help="Total iterations to run",
                      default=10)

    [opts, args] = parser.parse_args(args)
    if not opts.url or not opts.object_file or not opts.user_file:
        print "--url and --object_file and --user_file are required"
        sys.exit(0)

    return opts
     
     
def main(args = sys.argv):
    opts = parseOptions(args)
    st = ScalingTester(opts.url, opts.object_file, opts.user_file, \
                           opts.match_field, opts.filter_fields, \
                           opts.method, opts.client_location)

    num_iters = int(opts.num_iterations)
    for iter in range(num_iters):
        st.invoke(int(opts.num_concurrent))
        if iter < num_iters-1:
            time.sleep(int(opts.frequency))
    

if __name__ == "__main__":
    sys.exit(main())
    
    
