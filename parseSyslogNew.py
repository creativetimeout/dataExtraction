'''
dataExtraction.py
Created on 15 Jan 2017
@author: Jens Vossen

Purpose:
Browses through a specified logfile directory (inputDirectory) and extracts only relevant lines from logs.
Search terms are specified in Tuple 'searchItems'
outputs Logs in compressed format back to specified outputDirectory

Version History
v1.00    30.01.2017
v1.01    13.02.2017    Filter: UDP on Ports 53/137/138, Duration > 2:00
v1.02    13.02.2017    Filter: UDP on Port 161, Duration > 2:00
v1.03    20.02.2017    Key assembly with join
v1.04    22.02.2017    FirstSeen, lastSeen for every connection according to date of log file
v1.05    26.11.2017    Cleanup of unused or outdated fuctionality (removed splunk option)
                       Included total bytes transferred
v1.10    26.11.2017    Optimized dictionaries

'''
import gzip
import glob
import re
import datetime
import argparse
import sys

def logOutput(logMessage, logfile, logType="INFO"):
    try:
        outlog = open(logfile,"at")
        print('{}: {} - {}'.format(str(datetime.datetime.now()), logType, logMessage), file=outlog)
        outlog.close()
    except:
        print("Error writing to logfile: {}\n".format(logfile), sys.exc_info()[0])

def writeDictToFile(d, outDir):
    outFile = open(outDir,'wt')
    # CSV header
    # connSourceIP + ';' + connSourceZone +';' + connTargetIP + ';' + connTargetZone + ';' + connTargetPort + ';' + connType
    print('SourceIP;SourceZone;TargetIP;TargetZone;TargetPort;ConnectionType;count;firstSeen;lastSeen;totalBytes', file=outFile)
    for x in d:
        # Output key and the number of registered connections
        print(x + ';' + str(d[x][0]) + ";" + str(d[x][1]) + ";" + str(d[x][2]) + ";" + str(d[x][3]), file=outFile,)
    outFile.close()

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Browse through a specified logfile directory (inputDirectory) and extract only relevant lines from logs to a target directory (outputDirectory).")
    parser.add_argument("inputDirectory", help="input directory, where source files to be processed are stored.")
    parser.add_argument("outputDirectory", help="output directory, where generated files will be stored.")
    parser.add_argument("-e", "--encoding", help="encoding option, with which the inputDirectory files will be parsed. Defaults to 'latin-1'", choices=["latin-1", "utf-8"], default="latin-1")
    parser.add_argument("-v", "--verbose", help="generate console output during program execution.", action="store_true") # implement!
    args = parser.parse_args()

    encdg = args.encoding
    verbose = args.verbose
    inputDirectory = args.inputDirectory
    outputDirectory = args.outputDirectory

    if not inputDirectory.endswith('/'):
        inputDirectory = inputDirectory + "/"

    if not outputDirectory.endswith('/'):
        outputDirectory = outputDirectory + "/"
    logf = outputDirectory + "parseSyslogOutput.log"
    logOutput("*" * 40, logf)
    logOutput('Started dataExtraction.py', logf)

    if verbose:
        print("Input Directory:    {}\n" \
              "Output Directory:    {}".format(inputDirectory, outputDirectory))


    # Declare dictionary which will store accumulated connections
    connections = {}

    # -------- Following secion is valid for CISCO ASA Log Format
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

    searchItems = ('Teardown TCP', 'Teardown UDP')
    # -------- End of CISCO ASA specific log Format

    fileList = glob.glob(inputDirectory + '*')
    # Use the following syntax for a single file only.
    # fileList = ['/Volumes/home/TSY/Logfiles/DE_MBH_MUCALL_GW11/Uploaded/de-mbh-mucall-gw-11_2016-10-10.gz']

    for fileName in sorted(fileList):
        if fileName.endswith('.gz'):
            inFile = gzip.open(fileName, 'rt', encoding=encdg)
        else:
            open(fileName, 'rt', encoding=encdg)

        # outFile = gzip.open(outputDirectory + 'NewTeardown_' + fileName[fileName.rfind('/')+1:] + '.csv.gz','wt', encoding='utf-8')

        matchObj = regExFileDatePattern.match(fileName)

        if matchObj:
            fileYear = matchObj.group(1)
            fileMonth = matchObj.group(2)
            fileDay = matchObj.group(3)
            fileDate = datetime.date(int(fileYear), int(fileMonth), int(fileDay))
        else:
            print("Could not determine logfile date from filename!")
            logOutput('Could not determine logfile date from filename:{}'.format(fileName), logf)
            sys.exit()

        logOutput('Input Filename: ' + fileName, logf)
        if verbose: print("Processing file: {}".format(fileName))

        lineNumber = 0

        for line in inFile:
            lineNumber += 1
            if verbose:
                if (lineNumber % 10000) == 0:
                    print("*" * (int(lineNumber/100000)), end="")
                    print(" - {:,}".format(lineNumber), end="\r")

            # Restrict to relevant Teardown events, for which the regex is optimized.
            if any(s in line for s in searchItems):
                matchObj = regExPattern.match(line)
                if matchObj:
                    connDateTime    = matchObj.group('DateTime')
                    # print(matchObj.group('Hostname'))
                    # print(matchObj.group('ASA_Session'))
                    connType        = matchObj.group('ConnectionType')
                    # connID          = int(matchObj.group('ConnectionID'))
                    connSourceZone  = matchObj.group('SourceZone')
                    connSourceIP    = matchObj.group('SourceIP')
                    connSourcePort  = matchObj.group('SourcePort')
                    connTargetZone  = matchObj.group('TargetZone')
                    connTargetIP    = matchObj.group('TargetIP')
                    connTargetPort  = matchObj.group('TargetPort')
                    connDuration    = matchObj.group('Duration')
                    connBytes       = matchObj.group('Bytes')
                    connResult      = matchObj.group('Result')
                else:
                    logOutput("Regex did not catch relevant line: {}!".format(lineNumber), logf, 'ERROR')
                    logOutput(line, logf)


                # Check for relevance of log entry
                valid = True

                '''
                Workaround - duration can be more than 23 hours causing datetime to raise an exception
                to-do: clean exception handling
                '''
                hours = int(connDuration.split(':')[0])
                if (hours > 23):
                    hours=23
                    # logOutput('hours > 23: {} : {}/{}-{} bytes'.format(connDuration, connTargetPort, connType, connBytes), logf)

                duration = datetime.time( hours,
                                          int(connDuration.split(':')[1]),
                                          int(connDuration.split(':')[2]))
                # Ignore 0 byte entries
                if (int(connBytes) < 1):
                    valid = False
                else:
                    # Skip UDP Port 53, 137, 138 requests with timeouts (UDP does not supply TCP return values)
                    if (connType=="UDP") and (connTargetPort in ["53", "137", "138", "161"]) and (duration > datetime.time(0,1,59)):
                        valid = False

                if valid:

                    # Store unique connections with number of occurences in dictionary
                    key = ";".join([connSourceIP, connSourceZone, connTargetIP, connTargetZone, connTargetPort, connType])
                    if key in connections:
                        connections[key][0] += 1
                        # In case log files are not in sequential order, test dates
                        firstCompareDate = datetime.date(int(connections[key][1][0:4]),
                                                         int(connections[key][1][5:7]),
                                                         int(connections[key][1][8:10]))
                        lastCompareDate = datetime.date(int(connections[key][2][0:4]),
                                                        int(connections[key][2][5:7]),
                                                        int(connections[key][2][8:10]))
                        if firstCompareDate > fileDate:
                            connections[key][1] = fileDate.isoformat()
                        if lastCompareDate < fileDate:
                            connections[key][2] = fileDate.isoformat()



                        # firstSeen has already been set during initialization
                        connections[key][2] = fileDate.isoformat()
                        connections[key][3] += int(connBytes)
                    else:
                        # If no nonnections exist, then initialize
                        connections[key]= [1, fileDate.isoformat(),fileDate.isoformat(), int(connBytes)]   # numConnects, firstSeen, lastSeen, totalBytes

                else:
                    # Frequency of these cases is too high - removing logging // JV 13.02.2017
                    # if (int(connBytes) > 0): # This is the case, if presumably valid results failed the subsequent tests, e.g. DNS timeout.
                    #    logOutput('Ignoring: Port-{}, Duration-{}, Bytes-{}, Result-{}'.format(connTargetPort, connDuration, connBytes, connResult), logf)
                    pass

        if verbose:
            print("*" * (int(lineNumber/100000)), end="")
            print(" - {:,}".format(lineNumber))

        inFile.close()
        logOutput('Read {} lines.'.format(lineNumber), logf)
        logOutput('{} dictionary entries.'.format(len(connections)), logf)

    # Output connection dictionary to target file
    # No further conversion necessary, since dictionary keys are in CSV format
    connectionFile = outputDirectory + 'AllConnections.csv'
    logOutput('Writing connections to file {}'.format(connectionFile), logf)
    writeDictToFile(connections, connectionFile)
    logOutput('Completed', logf)
    logOutput(("*" * 40) + "\n" , logf)

if __name__ == "__main__": main()
