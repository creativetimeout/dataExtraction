'''
threadedParseSyslog.py
Syslog parser to generate accumulated connections
'''
import time
import argparse
import glob
import re
import datetime
import threading
from queue import Queue
import LogFileExtractor as LFE
         
def writeDictToFile(d, firstSeen, lastSeen, outDir):
    outFile = open(outDir,'wt')
    # CSV header
    # connSourceIP + ';' + connSourceZone +';' + connTargetIP + ';' + connTargetZone + ';' + connTargetPort + ';' + connType
    print('SourceIP;SourceZone;TargetIP;TargetZone;TargetPort;ConnectionType;count;firstSeen;lastSeen', file=outFile)
    for x in d:
        # Output key and the number of registered connections
        print(x + ';' + str(d[x]) + ";" + firstSeen[x] + ";" + lastSeen[x], file=outFile,)
    outFile.close()
    
def processFile(fileName):
    with print_lock:
        print('{}\n{}'.format(fileName, threading.current_thread().name))
        
    parsefile = LFE.LogFileExtractor(fileName, encdg, regExPattern, regExFileDatePattern)
    connections, firstSeen, lastSeen = parsefile.extractData()
    with dict_lock:
        for k in connections.keys():
            if k in sumConnections.keys():
                sumConnections[k] += connections[k]
            else:
                sumConnections[k] = connections[k] 
    
        for k in firstSeen.keys():
            if k in sumFirstSeen.keys():
                # get iso formatted date and convert to datetime
                firstCompareDate = datetime.date(int(sumFirstSeen[k][0:4]), 
                                                 int(sumFirstSeen[k][5:7]), 
                                                 int(sumFirstSeen[k][8:10]))
                curDate = datetime.date(int(firstSeen[k][0:4]), 
                                                 int(firstSeen[k][5:7]), 
                                                 int(firstSeen[k][8:10]))
                if curDate < firstCompareDate:
                    sumFirstSeen[k] = firstSeen[k]
            else:
                sumFirstSeen[k] = firstSeen[k]
                    
        for k in lastSeen.keys():  
            if k in sumLastSeen.keys():
                # get iso formatted date and convert to datetime
                lastCompareDate = datetime.date(int(sumLastSeen[k][0:4]), 
                                                 int(sumLastSeen[k][5:7]), 
                                                 int(sumLastSeen[k][8:10]))
                curDate = datetime.date(int(firstSeen[k][0:4]), 
                                                 int(lastSeen[k][5:7]), 
                                                 int(lastSeen[k][8:10]))
                if curDate > lastCompareDate:
                    sumLastSeen[k] = lastSeen[k]
            else:
                sumLastSeen[k] = lastSeen[k]
                          
    with print_lock:
        print ('File Done: {}\n - {} dictionary entries\n - {} total dictionary entries.'.format(fileName, len(connections), len(sumConnections)))
               
# The threader thread pulls a worker from the queue and processes it
def threader():
    while True:
        # gets an worker from the queue
        worker = q.get()
        # Run the example job with the avail worker in queue (thread)
        processFile(worker)
        # completed with the job
        q.task_done()

# ------------------------  Start of execution routine ----------------
# Parse command line arguments
parser = argparse.ArgumentParser(description="Browse through a specified logfile directory (inputDirectory) and extract only relevant lines from logs to a target directory (outputDirectory).")
parser.add_argument("-i", "--inputDirectory", help="directory in which source files to be processed are located. Watch out not to have any further subdirectories in this dir.", required=True)
parser.add_argument("-o", "--outputDirectory", help="directory in which all generated output files will be placed.", required=True)
parser.add_argument("-e", "--encoding", help="encoding option with which the inputDirectory files will be parsed. Defaults to 'latin-1'", choices=["latin-1", "utf-8"], default="latin-1")
parser.add_argument("-t", "--threads", help="specify number of threads which shall be executed in parallel.", type=int, default=2, choices=range(1,11))
 # implement!
args = parser.parse_args()
    
encdg = args.encoding
# Setup Directories for in- and output ----------------------
inputDirectory = args.inputDirectory
outputDirectory = args.outputDirectory
if not inputDirectory.endswith('/'):
    inputDirectory = inputDirectory + "/"

if not outputDirectory.endswith('/'):
    outputDirectory = outputDirectory + "/"

connectionFile = outputDirectory + 'AllConnections.csv'

# Create the queue and threader 
q = Queue()

# Prepare locks----------------------------------------------
print_lock = threading.Lock()
dict_lock = threading.Lock()

# Receiving dictionaries for thread results ------------------
sumConnections = {}
sumLastSeen = {}
sumFirstSeen = {}


# Regular expression for syslog elements matching.
# Compile here only once to avoid pattern interpretation for every further use.
regExPattern = re.compile(r'^(?P<DateTime>\w+\s+\d+\s+(\d+):(\d+):(\d+))\s(?P<Hostname>\S+)'\
                        '\s:\s\w+\s\d+\s(\d+):(\d+):(\d+)\s\w+:\s(?P<ASA_Session>\S+)\s(?:Teardown)'\
                        '\s(?P<ConnectionType>\S+)\s(\S+)\s(?P<ConnectionID>\d+)' \
                        '\sfor\s(?P<SourceZone>\S+):(?P<SourceIP>\d+.\d+.\d+.\d+)/(?P<SourcePort>\d+)(\(any\))*'\
                        '\sto\s(?P<TargetZone>\S+):(?P<TargetIP>\d+.\d+.\d+.\d+)/(?P<TargetPort>\d+)(\(any\))*\s'\
                        '(duration)\s(?P<Duration>\d+:\d+:\d+)\s(bytes)\s(?P<Bytes>\d+)'\
                        '\s*(?P<Result>.*)' 
                      ) 

regExFileDatePattern = re.compile(r'.*(\d{4})-(\d{2})-(\d{2}).*')
   
# how many threads are we going to allow for
for x in range(args.threads):
     t = threading.Thread(target=threader)
     # classifying as a daemon, so they will die when the main dies
     t.daemon = True
     # begins, must come after daemon definition
     t.start()
start = time.time()
# ------ This is where the music is playing ------------
fileList = glob.glob(inputDirectory + '*')
      
for fileName in sorted(fileList):
    q.put(fileName)


# wait until the thread terminates.
q.join()

writeDictToFile(sumConnections, sumFirstSeen, sumLastSeen, connectionFile)

print('Total job execution time: ',time.time() - start)

