"""

Multi-processed MD5 hash brute forcer

Hengjie (C) 2012. All rights reserved.

:Author: Hengjie
:Created: 2012-03-19

"""

import hashlib
import sys
from pprint import pprint as pp
from multiprocessing import Process, Queue, Event, Manager
from Queue import Empty
import atexit
import time
import random

# Hash to bruteforce
hash = "8b1a9953c4611296a827abf8c47804d7"

# ASCII Ranges
easyRange = [32,33,36,42,43] + range(48, 58) + range(65, 91) + range(97, 123)
allRange = range(32,127)

class MD5Cracker(Process):
    def __init__(self, queue, global_namespace):

        self.global_namespace = global_namespace

        self.alive = Event()
        self.alive.set()
        self.queue = queue
        super(MD5Cracker, self).__init__()

        self.internal_count = 0
        self.internal_mod = random.randint(500, 1000)

    def checkPassword(self, password):
        '''Check to see if password matches hash'''

        # count
        self.internal_count += 1

        # Batch update of global_namespace to prevent locking
        if self.internal_count % self.internal_mod == 0:
            self.global_namespace.count += self.internal_count
            self.internal_count = 0

        # check MD5 hash
        if (hashlib.md5(password).hexdigest() == hash):
            print "match: {}".format(password)
            self.global_namespace.finished = True
            sys.exit()

    def run(self):
        '''Take a job from the queue and crunch on it'''

        # If join()'ed then we stop recursively digging deeper
        while self.alive.is_set():

            try:
                job = self.queue.get(timeout=1.0)
            except Empty:
                continue

            width = job['width']
            position = job['position']
            baseString = str(job['baseString'])

            # current position
            for char in easyRange:

                self.checkPassword(baseString + "%c" % char)

                if (position < width - 1):
                    # Split the work to other workers or 
                    # if the problem size is small enough, then we do it ourselves
                    # 
                    # TODO: Have a better way of calculating how much work to do before we do it in the own worker
                    if position < width - 3:
                        self.queue.put({'width': width, 'position': position + 1, 'baseString': (baseString + "%c" % char)})
                    else:
                        self.recurse(width, position + 1, baseString + "%c" % char)


    def recurse(self, width, position, baseString):
        '''Once the crackable problem space is small enough.
        We will run this instead of adding the job into the queue so
        that we can start utilising this process to 100%'''
        for char in easyRange:
            self.checkPassword(baseString + "%c" % char)

            if (position < width - 1):
                # If join()'ed then we stop recursively digging deeper
                if self.alive.is_set():
                    self.recurse(width, position + 1, baseString + "%c" % char)

    def join(self, timeout=None):
        '''Signal the run() to shutdown before joining'''

        self.alive.clear()
        super(MD5Cracker, self).join(timeout)

# Graceful clean up
def cleanup():
    for worker in workers:
        worker.join()
atexit.register(cleanup)

# init vars
workers = []
work_queue = Manager().Queue()
global_namespace = Manager().Namespace()
global_namespace.finished = False
global_namespace.count = 0

# Set up Processes
number_of_processes = 16
for i in range(number_of_processes):
    worker = MD5Cracker(work_queue, global_namespace)
    worker.start()
    workers.append(worker)

print "Target Hash: {}".format(hash)

maxChars = 13
while_count = 1
for baseWidth in range(1, maxChars + 1):

    while global_namespace.finished is False:
        if work_queue.empty():
            print "checking passwords width [" + `baseWidth` + "]"

            # set is width, position, baseString
            work_queue.put({'width': baseWidth, 'position': 0, 'baseString': ""})
            break
        else:

            if while_count % 10 == 0:
                global_namespace.count = 0
                while_count = 1
            else:
                print "{:,d} passwords/sec".format(global_namespace.count/while_count)
                while_count += 1

            print "Queue Size: {}".format(work_queue.qsize())
            time.sleep(1)
            continue