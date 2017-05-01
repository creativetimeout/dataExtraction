import gzip
import datetime

class LogFileExtractor:
    
    def __init__(self, fileName, encoding, regExPattern, regExFileDatePattern):
        self.fileName = fileName
        self.encdg = encoding
        self.regExPattern = regExPattern
        self.regExFileDatePattern = regExFileDatePattern
        # Declare dictionaries which will store accumulated connections
        self.connections = {}
        self.firstSeen = {}
        self.lastSeen = {}
        
    def extractData(self):
        # Open File
        if self.fileName.endswith('.gz'):
            inFile = gzip.open(self.fileName, 'rt', encoding=self.encdg)
        else:
            inFile = open(self.fileName, 'rt', encoding=self.encdg)
        
        matchObj = self.regExFileDatePattern.match(self.fileName)

        if matchObj:
            fileYear = matchObj.group(1)
            fileMonth = matchObj.group(2)
            fileDay = matchObj.group(3)
        else:
            fileYear = '1970'
            fileMonth = '01'
            fileDay = '01'
        
        fileDate = datetime.date(int(fileYear), int(fileMonth), int(fileDay))
        
        searchItems = ('Teardown TCP', 'Teardown UDP') 
        lineNumber = 0
        
        for line in inFile:
            lineNumber += 1 
            # Restrict to relevant Teardown events, for which the regex is optimized.
            if any(s in line for s in searchItems):
                matchObj = self.regExPattern.match(line)
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
                    ##############
                    # logOutput("Regex did not catch relevant line: {}!".format(lineNumber), logf, 'ERROR')
                    pass
            
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
                    if key in self.connections:
                        self.connections[key] += 1
                    else:
                        self.connections[key] = 1
                        
                    if key in self.firstSeen:
                        # get iso formatted date and convert to datetime
                        firstCompareDate = datetime.date(int(self.firstSeen[key][0:4]), 
                                                         int(self.firstSeen[key][5:7]), 
                                                         int(self.firstSeen[key][8:10]))
                        lastCompareDate = datetime.date(int(self.lastSeen[key][0:4]), 
                                                        int(self.lastSeen[key][5:7]), 
                                                        int(self.lastSeen[key][8:10]))
                        if firstCompareDate > fileDate: 
                            self.firstSeen[key] = fileDate.isoformat()
                        if lastCompareDate < fileDate:  
                            self.lastSeen[key] = fileDate.isoformat()
                    else:
                        self.firstSeen[key] = fileDate.isoformat()
                        self.lastSeen[key] = self.firstSeen[key]
    
        inFile.close()    
        return self.connections, self.firstSeen, self.lastSeen
        