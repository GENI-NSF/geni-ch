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

import os
import sys
import threading
import time

# Simple threaded base class that checks whether a particular
# file has changed and calls the base class method handeFileChange 
# when it has changed (based on change to OS file modified time
class FileChecker(threading.Thread):
    def __init__(self, filename, interval):
        threading.Thread.__init__(self)
        self._filename = filename
        self._interval = interval
        self._file_time = os.stat(self._filename).st_mtime
        self._running = False

    # Thread 'run' method: Loop and check if the file modify time has
    # changed since last time around the loop. If so, update time 
    # and invoke handleFileChange method
    def run(self):
        self._running = True
        while self._running:
            time.sleep(self._interval)
            new_file_time = os.stat(self._filename).st_mtime
            if self._file_time < new_file_time:
                self._file_time = new_file_time
                self.handleFileChange()

    # Base method called 
    def handleFileChange(self):
        print "File changed: %s %s" % (self._filename, self._file_time)

    # Kill the searching thread, to drop out of the 'run' loop after next sleep
    def stop(self): self._running = False
        
# Simple test program: Runs for 50 seconds, counting the seconds
# And spawning a FileChecker to check on /tmp/foo.txt
def main():
    filename = '/tmp/foo.txt'
    # Make sure file is there
    try:
        open(filename, 'r').close()
    except Exception:
        open(filename, 'w').close()

    checker = FileChecker('/tmp/foo.txt', 5)
    checker.start()
    for i in range(50):
        print "I = %d" % i
        time.sleep(1)

    checker.stop()


if __name__ == "__main__":
    sys.exit(main())

