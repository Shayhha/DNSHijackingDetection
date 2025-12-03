import sys, os, re, base64, datetime, requests
from dotenv import load_dotenv
from scapy.all import Packet, TCP, UDP, IP, DNS, DNSQR, DNSRR, send, sniff

currentDir = os.path.dirname(os.path.abspath(__file__)) #represents current directory

#===============================================================DNSResponse======================================================================#

#Class that reprsents a DNS response packet
class DNSResponse():
    #Constructor of class
    def __init__(self, srcIp: str, dstIp: str, srcPort: int, dstPort: int, pktid: int, responseName: str, responseType: str, responseClass: str, numResponses: int, responseData: str) -> None:
        self.srcIp = srcIp
        self.dstIp = dstIp
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.pktid = pktid
        self.responseName = responseName
        self.responseType = responseType
        self.responseClass = responseClass
        self.numResponses = numResponses
        self.responseData = responseData
        
    #Method for printing info of DNS response packet
    def ShowInfo(self) -> None:
        output = f'Type: DNS Response\n' #type of packet
        output += f'Source IP: {self.srcIp} | Port: {self.srcPort}\n' #source ip and port
        output += f'Destination IP: {self.dstIp} | Port: {self.dstPort}\n' #destination ip and port
        output += f'ID: {self.pktid}\n' #id of the dns packet
        output += f'Response Name: \033[93m{self.responseName}\033[0m\n' #response name like domain of website
        output += f'Response Type: {self.responseType}\n' #response type of dns packet like A, MX or TXT records
        output += f'Response Class: {self.responseClass}\n' #response class of packet
        output += f'Num Responses: {self.numResponses}\n' #number of responses inside packet
        if self.responseData != '': #if responseData isnt empty we print it
            output += f'Response Data: \033[93m{self.responseData}\033[0m' #responseData is the given text inside the dns response payload
        print(output) #print the packet 

#===============================================================DNSResponse-END==================================================================#

#=================================================================DNSSniffer=====================================================================#

#Static class for sniffing DNS response packets
class DNSSniffer():
    suspiciousDomains: list = [] #represents a list containing all the domains we flagged as suspicious
    numOfRequests: int = 4 #represnets the number of domian report requests allowed for VirusTotal (4 requests per minute)
    isRunning: bool = False #represents the state of the sniffer

    #Function for checking if given packet is DNS response TXT packet
    @staticmethod        
    def CheckDNSResponseTXT(packet: Packet) -> DNSResponse | None:
        DNSClassTypes = {1: 'IN', 2: 'CS', 3: 'CH', 4: 'HS', 255: 'ANY'} #dict that holdes the values for dns class types
        #We're interested in packets with a DNS response layer and of type TXT record
        if DNS in packet: #check if packet is DNS packet
            dnsPacket = packet[DNS] #save dns packet in variable
            if IP in packet and (packet.haslayer(TCP) or packet.haslayer(UDP)) : #if true means packet has ip layer and its tcp or udp
                srcIp = packet[IP].src #save packet source port
                dstIp = packet[IP].dst #save packet destination port
                srcPort = packet.sport #save packet source ip
                dstPort = packet.dport #save packet destination port
            if dnsPacket.qr == 1 and dnsPacket.an and dnsPacket.an[0].type == 16: #we check if the packet is response packet if qr is 1 and that its type is 16 (means its a TXT record)
                pktId = dnsPacket.id #save id of packet
                responseName = ToString(dnsPacket.an[0].rrname) #save repsonse name of packet (domain)
                responseType = 'TXT' #save response type of packet
                responseClass = DNSClassTypes[dnsPacket.an[0].rclass] if dnsPacket.an[0].rclass in DNSClassTypes else dnsPacket.an[0].rclass #save the class type from dict 
                numResponses = dnsPacket.ancount #save number of responses of packet
                responseData = '' #save reponse data from the packet's payload 
                if hasattr(dnsPacket.an[0], 'rdata'): #check if rdata attribute exists
                    responseData += ToString(dnsPacket.an[0].rdata) #add the data from the payload from rdata parameter 
                return DNSResponse(srcIp, dstIp, srcPort, dstPort, pktId, responseName, responseType, responseClass, numResponses, responseData) #return DNSResponse object if we successfully find one
        return None #else we return none indicating that we didn't find a DNS TXT response packet


    #Function for sniffing packets and handle our DNS TXT response packets accordingly
    @staticmethod
    def SniffPackets(packet: Packet) -> None:
        DNSResponsPkt = DNSSniffer.CheckDNSResponseTXT(packet) #save result from func inside our DNSResponsePkt variable
        if DNSResponsPkt != None: #check if our object isn't None, means we captured a DNS TXT resposne packet
            if DNSResponsPkt.responseData != '': #check if dns packet has response data
                if IsCommand(DNSResponsPkt.responseData) and DNSResponsPkt.responseName not in DNSSniffer.suspiciousDomains:
                    DNSSniffer.suspiciousDomains.append(DNSResponsPkt.responseName)
                    DNSSniffer.numOfRequests -= 1
                    PrintMessage(f'Found suspicious DNS response packet that includes valid command: \033[95m{DNSResponsPkt.responseData}\033[0m', 'success')
                    print('============================== DNS Packet Info ==============================')
                    DNSResponsPkt.ShowInfo() #print packet info
                    print('=============================== Domain Report ===============================')
                    domainReportDict = GetDomainReport(DNSResponsPkt.responseName) #get domain report dictionary from virusTotal 
                    PrintDomainReport(domainReportDict) #print domain report
                    print('=============================================================================\n\n')
                elif IsBase64(DNSResponsPkt.responseData) and DNSResponsPkt.responseName not in DNSSniffer.suspiciousDomains:
                    DNSSniffer.suspiciousDomains.append(DNSResponsPkt.responseName)
                    DNSSniffer.numOfRequests -= 1
                    PrintMessage(f'Found suspicious DNS response packet that includes base64 encoded data: \033[95m{DNSResponsPkt.responseData}\033[0m', 'success')
                    print('============================== DNS Packet Info ==============================')
                    DNSResponsPkt.ShowInfo() #print packet info
                    print(f'Decoded Response Data: \033[93m{DecodeBase64(DNSResponsPkt.responseData)}\033[0m') #print decoded response data
                    print('=============================== Domain Report ===============================')
                    domainReportDict = GetDomainReport(DNSResponsPkt.responseName) #get domain report dictionary from virusTotal 
                    PrintDomainReport(domainReportDict) #print domain report
                    print('=============================================================================\n\n')
         

    #Function for checking the state of numOfRequests
    @staticmethod
    def CheckNumOfRequests(packet: Packet) -> bool:
        if DNSSniffer.numOfRequests == 0:
            DNSSniffer.isRunning = False #set isRunning to false
            DNSSniffer.suspiciousDomains.clear() #clear suspiciousDomains list for next scan
            DNSSniffer.numOfRequests = 4 #set the numOfRequests back to 4 for next scan
            PrintMessage('Reached maximum capacity of requests for domain report, stopping scan...\n', 'info')
            return True #return true if numOfRequests is 0 indicating when to stop sniffing
        else:
            return False #else we continue the sniffing
    

    #Function for initializing the packet sniffing method for detecting DNS hijacking attemts
    @staticmethod
    def InitSniff() -> None:
        if DNSSniffer.isRunning: #if true it means that a scan is currently running 
            PrintMessage('Cannot initialize scan before current scan finishes.\n', 'fail') #print that scan cannot be initialized
        else: #else we can proceed with initializing the scan
            PrintMessage('Scanning for potential DNS hijacking traffic...\n', 'info') #print that scan is being initialized
            DNSSniffer.isRunning = True #set isRunning to true indicating that sniffer in progress
            #start the sniffing with sniff method from scapy with desired parameters and stop  filter set to our method
            sniff(prn=DNSSniffer.SniffPackets, filter='udp port 53', stop_filter=DNSSniffer.CheckNumOfRequests, store=False)
            

#==================================================================DNSSniffer-END================================================================#

#=================================================================HelperFunctions================================================================#

#Function for crafting DNS TXT response packet
def SendDNSTXTResponse(sourceIp: str, destinationIp: str, queryDomain: str, txtResponse: str) -> None:
    dnsResponse = IP(src=sourceIp, dst=destinationIp)/UDP(dport=53)/DNS(
        id=1000, #Packet ID
        qr=1,  #Response packet
        opcode=0,  #Standard query
        aa=1,  #Authoritative Answer
        rcode=0,  #No error
        qd=DNSQR(qname=queryDomain, qtype=16), #Query for TXT record
        an=DNSRR(rrname=queryDomain, type=16, ttl=600, rdata=txtResponse) #Answer with TXT record
    )
    send(dnsResponse, verbose=False) #Send the packet to our desired ip address
    

#Function for sending DNS TXT response packets for simulating attack
def SendDNSPackets() -> None:
    print('DNS Response Traffic Simulator\n')
    sourceIp = input('Enter source IP: ')
    destinationIp = input('Enter destination IP: ')
    queryDomain = input('Enter query domain: ')
    txtResponse = input('Enter TXT response: ')
    numPackets = int(input('Enter number of packets to send: '))
    
    PrintMessage('Sending DNS response packets...', 'info')
    for i in range(numPackets): #send packets in a loop
        SendDNSTXTResponse(sourceIp, destinationIp, queryDomain, txtResponse) #call our fucntion to send the packet
        PrintMessage(f'DNS packet no. {i + 1} sent..', 'info')
    PrintMessage('Finished sending DNS packets.', 'success')
    

#Function for sending random DNS TXT response packets for simulating attack
def SendRandomDNSPackets() -> None:
    suspiciousDomains = [('3.141.96.53', 'news-spot.live'), ('172.67.154.10', 'onerecycleclub.com'), ('35.186.223.180', 'todaysport.live'), ('172.67.131.239', 'inpsct.top')] #list represents domains that are known to be malicious
    suspiciousResponses = ['bmV0c2ggaW50ZXJmYWNlIGlwIHNob3cgZG5zc2VydmVycw==', 'ipconfig /flushdns', 'netsh interface ipv4 show dns', 'bmV0c2ggaW50ZXJmYWNlIGlwdjQgZGVsZXRlIGRuc3NlcnZlciAiRXRoZXJuZXQiIDE5Mi4xNjguMS4x'] #list represents suspicious data that isn't typical in dns txt packets
    print('DNS Response Traffic Simulator\n')
    destinationIp = input('Enter destination IP: ')
    PrintMessage('Sending random DNS response packets...', 'info')
    for i, (domain, response) in enumerate(zip(suspiciousDomains, suspiciousResponses)): #iterate over both lists to send packets
        SendDNSTXTResponse(domain[0], destinationIp, domain[1], response) #call our fucntion to send the packet
        PrintMessage(f'DNS packet no. {i + 1} sent..', 'info')
    PrintMessage('Finished sending DNS packets.', 'success')
    

#Function for printing messages to console
def PrintMessage(strData: str, msgType: str='info') -> None:
    if msgType == 'info':
        print(f'\033[94m[*]\033[0m {strData}')
    elif msgType == 'success':
        print(f'\033[92m[+]\033[0m {strData}')
    elif msgType == 'fail':
        print(f'\033[91m[-]\033[0m {strData}')
    elif msgType == 'warning':
        print(f'\033[91m[*]\033[0m {strData}')
        

#Function for converting a data type like list or byte to string
def ToString(data: int | bytes | list) -> str: 
    if data != None: #if data not none we continue
        if isinstance(data, bytes): #if given data is byte we convert it to utf-8 string
            data = data.decode('utf-8', 'replace') #decode the byte to string
        elif isinstance(data, list): #if given data is list we convert it to utf-8 string
            data = ', '.join(item.decode('utf-8', 'replace') if isinstance(item, bytes) else str(item) for item in data) #decode the list into string
        data = data.rstrip('.') #remove the trailing dot
    return data
            

#Function to convert from timestamp to a date (from virusTotal api)
def ToDatetime(timestamp: str) -> datetime.datetime | None: 
    if timestamp != None:
        return datetime.datetime.fromtimestamp(timestamp) #return the date with datetime function
    return None


#Function for checking if given date has been created recently
def CheckDatetime(date: datetime.datetime) -> bool:
    if date != None:
        currentDate = datetime.datetime.now() #represents current date
        previousDate = currentDate - datetime.timedelta(days=365) #represents the date one year ago
        return date > previousDate #return if given date was created recently
    return False
 

#Function for decoding base64 string
def DecodeBase64(dataStr: str) -> str:
    try:
        decodedBytes = base64.b64decode(dataStr) #decode the base64 string
        try:
            return decodedBytes.decode('utf-8') #try to decode to utf-8
        except UnicodeDecodeError: #if failed decoding to utf-8
            return decodedBytes #return the raw bytes
    except Exception as e: #if exception is thrown while decoding
        return f'Error decoding base64 string: {str(e)}.' #return an error
    

#Function for checking if the given string is encoded in base64
def IsBase64(dataStr: str) -> bool:
    base64Regex = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$' #regular expression for base64 encoded strings
    match = re.fullmatch(base64Regex, dataStr) #check if the dataStr matches the regular expression of base64
    if match: #if dataStr matches base64 encoded str, we return true
        return True
    else: #else it doesnt match base64 so we return false
        return False
    

#Function for checking if given string contains a valid cmd/powershell command
def IsCommand(dataStr: str) -> bool:
    windowsCommands = [
        #Common CMD Commands
        'dir', 'cd', 'md', 'mkdir', 'rd', 'rmdir', 'copy', 'move', 'del', 'ren', 'echo', 'type', 'cls', 'taskkill',
        'ping', 'tracert', 'ipconfig', 'whoami', 'systeminfo', 'netstat', 'tasklist', 'netsh', 'nslookup', 'start',
    
        #Common PowerShell Commands
        'Get-ChildItem', 'Set-Location', 'New-Item', 'Remove-Item', 'Copy-Item', 'Move-Item', 'Remove-Item', 
        'Rename-Item', 'Write-Output', 'Get-Content', 'Clear-Host', 'Test-Connection', 'Get-NetIPAddress',
        'Get-NetTCPConnection','Get-Process', 'Start-Process', 'Stop-Process',
    
        #DNS-related Commands
        'netsh interface ipv4 show dns', 
        'netsh interface ipv4 add dnsserver',  
        'netsh interface ipv4 delete dnsserver',  
        'netsh interface ipv6 show dns',  
        'netsh interface ipv6 add dnsserver', 
        'netsh interface ipv6 delete dnsserver',  
        'netsh interface ip show dnsservers',
        'netsh interface set dnsserver', 
        'netsh interface ip set dns'
    ]
    dataStr = dataStr.strip()  #remove leading/trailing whitespace
    return any(command.lower() in dataStr.lower() for command in windowsCommands) #return true if given dataStr includes valid command


#Function that utilizes VirusTotal api to retrive domain report for a specific domain in interest
def GetDomainReport(domain: str) -> dict | None:
    #load environment variables from env file and retrieve the VirusTotal API key
    load_dotenv(dotenv_path=os.path.join(currentDir, 'config', '.env')) #load .env file
    virusTotalApiKey = os.getenv('VIRUS_TOTAL_API_KEY') #get the api key from .env file

    if not virusTotalApiKey: #means api key is not given
        return None #return none to indicate failure

    url = f'https://www.virustotal.com/api/v3/domains/{domain}' #VirusTotal url for domain report
    headers = {
        'accept': 'application/json',
        'x-apikey': virusTotalApiKey
    }
    response = requests.get(url, headers=headers) #sent the http request to VirusTotal 
    
    if response.status_code == 200: #successful response
        data = response.json() #represents a dict that includes info from domain report
        #these are parameters we're interested in for our domian report
        lastAysStats = data['data']['attributes'].get('last_analysis_stats') #represents the amount of browsers flagged the doamin as malicious or harmless etc.
        totalVotes = data['data']['attributes'].get('total_votes') #represents total votes (malicious or harmless) for the domain by VirusTotal community
        reputation = data['data']['attributes'].get('reputation') #represents the reputation of the website (if higher number it means its safe)
        creationDate = ToDatetime(data['data']['attributes'].get('creation_date')) #represents domian's date of creation 
        return {'domain': domain, 'lastAysStats': lastAysStats, 'totalVotes': totalVotes, 'reputation': reputation, 'creationDate': creationDate} #return dictionary of domain report 
    else: #other status codes mean we failed to retrive domain report, maybe due to rate limit (4 requests per minute)
        return None #return none to indicate failure
    
 
#Function that prints domain report from given report dictionary
def PrintDomainReport(reportDict: dict) -> None:
    if reportDict:
        output = f'Domain Name: \033[93m{reportDict['domain']}\033[0m\n' #add domain name to output
        output += f'Last Analysis Stats:\n' #add analysis stats 
        for key, value in reportDict['lastAysStats'].items(): #iterate over dict and add each value to output
            output += f' - {key.capitalize()}: {value}\n'
        output += f'Total Votes:\n'
        for key, value in reportDict['totalVotes'].items(): #iterate over dict and add each value to output
            output += f' - {key.capitalize()}: {value}\n'
        output += f'Reputation Score: {reportDict['reputation']}\n' #add score to output
        output += f'Creation Date: {reportDict['creationDate']}' #add creation date to output
        print(output) #print the domain report
        
        #check status of domain and show user message about it
        if reportDict['lastAysStats']['malicious'] > 0 and CheckDatetime(reportDict['creationDate']): #means domain was flagged as malicious and was created recently
            PrintMessage(f'The domian "{reportDict['domain']}" has been reported as malicious and was created recently.', 'warning')
        elif reportDict['lastAysStats']['suspicious'] > 0 and CheckDatetime(reportDict['creationDate']): #means domain was flagged as suspicious and was created recently
            PrintMessage(f'The domian "{reportDict['domain']}" has been reported as suspicious and was created recently.', 'warning')
        elif reportDict['lastAysStats']['malicious'] > 0: #means domain was flagged as malicious
            PrintMessage(f'The domian "{reportDict['domain']}" has been reported as malicious.', 'warning')
        elif reportDict['lastAysStats']['suspicious'] > 0: #means domain was flagged as suspicious
            PrintMessage(f'The domian "{reportDict['domain']}" has been reported as suspicious.', 'warning')
        elif CheckDatetime(reportDict['creationDate']): #means domian was created recently
            PrintMessage(f'The domian "{reportDict['domain']}" was created recently.', 'warning')
        else: #else domain has no known malicious activity 
            PrintMessage(f'The domian "{reportDict['domain']}" has no reported malicious activity.', 'info')
    else:
        PrintMessage(f'Could not fetch domain report, please try again later.', 'fail') #show error message if dict is empty, means we didn't receive info from virusTotal


#Main function of application
def main() -> None:    
    print('''
 ____  _   _ ____    _   _ _  _            _    _             
|  _ \\| \\ | / ___|  | | | (_)(_) __ _  ___| | _(_)_ __   __ _ 
| | | |  \\| \\___ \\  | |_| | || |/ _` |/ __| |/ / | '_ \\ / _` |
| |_| | |\\  |___) | |  _  | || | (_| | (__|   <| | | | | (_| |
|____/|_| \\_|____/  |_| |_|_|/ |\\__,_|\\___|_|\\_\\_|_| |_|\\__, |
                           |__/                         |___/ 
''')

    print('DNS Hijacking Detection\n') #print name of program
    #PrintDomainReport(GetDomainReport('reddit.com'))
    #print(IsCommand('ipconfig /all'))
    while True:
        print('Please choose desired operation:\n')
        print('[1] Scan for DNS hijacking attacks.')
        print('[2] Send DNS TXT response packets.')
        print('[3] Send random suspicious DNS TXT response packets.')
        print('[4] Exit.\n')
        choice = input('Enter your choice: ')
        print('')
        if choice == '1':
            DNSSniffer.InitSniff() #start the scan for DNS response packets
            print('')
        elif choice == '2':
            SendDNSPackets() #call our function to send custom DNS response packets 
            print('')
        elif choice == '3':
            SendRandomDNSPackets() #call our function to send random DNS response packets 
            print('')
        elif choice == '4':
            print('Exiting.')
            break
        else:
            PrintMessage('Invalid choice, Please try again.\n', 'fail')

if __name__ == '__main__':
    main()