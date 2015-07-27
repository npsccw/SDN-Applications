from dpkt import *
from ryu.base import app_manager
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
import requests
import hashlib

#Global Vars
fingerprintList = []
MACfingerprintLIST = {}
test = "test"
cookiejar = []

def hexToIP(h):
    return `int(h[2:3],16)` + '.' + `int(h[3:5],16)` + '.' + `int(h[5:7],16)` + '.' + `int(h[7:9],16)`

def compare(ListofFingerprints, incomingParsedDHCP):
    ##    [dhcp1.xid ,dhcp1.chaddr ,dhcp1.ciaddr ,dhcp1.data ,dhcp1.file ,dhcp1.flags ,dhcp1.giaddr
    ##     ,dhcp1.hln ,dhcp1.hops ,dhcp1.hrd ,dhcp1.magic ,dhcp1.op ,dhcp1.opts ,dhcp1.secs ,dhcp1.siaddr
    ##    ,dhcp1.sname ,dhcp1.yiaddr]

    ## This function will compare a dpkt library parsed DHCP packet with the Satori DHCP XML fingerprints.
    
    #dhcpList = dhcpParse(incomingParsedDHCP)
    #print dhcpList
    global fingerprintList
    fingerprintList = ListofFingerprints

    option53 = None
    option50 = None
    option12 = None
    option55 = None
    option60 = None
    weight = None
    

######search for DHCP fields in an incoming packet################################################
    ##Currently a for list will remove later, assumes that each packet will arrive sequentiall
    for x in range(len(incomingParsedDHCP)):
        hitList = []
        
        ##dhcpList[parsed DHCP packet][Index 12 is where the DHCP Message options are...
        ##                             bc, that's how they are parsed]
        optionsList = incomingParsedDHCP[x][12]
        
        ##iterate through the options of the DHCP packet
        ##extract the DHCP Message Type, ie, Request, Discover...
        try:
            option53 = dhcpMsgHasOption(optionsList,53).encode('hex')
            #print "option53 " + option53
        except (AttributeError, TypeError):
            pass
        
        ##extract the Requested IP options
        try:
            option50 = dhcpMsgHasOption(optionsList,50).encode('hex')
            #print "option50 " + option50
        except (AttributeError, TypeError):
            pass

        ##extract the host name, is a string
        try:
            option12 = dhcpMsgHasOption(optionsList,12)
            #print "option12 " + option12
        except (AttributeError, TypeError):
            pass

        ## extract DHCP 55 client parameters request list
        try:
            option55 = dhcpMsgHasOption(optionsList,55).encode('hex')
            #print "option55 " + option55
        except (AttributeError, TypeError):
            pass
        
        ## extract vendor class-ID, ie "MSFT 5.0", is a string
        try:
            option60 = dhcpMsgHasOption(optionsList,60)
            #print "option60 " + option60
        except (AttributeError, TypeError):
            pass

        ## Compare the DHCP type to compare w/ fingerprint
        dhcptype = None
        if option53:
            if option53 == '01':
                dhcptype = 'Discover'
            if option53 == '02':
                dhcptype = 'Offer'    
            if option53 == '03':
                dhcptype = 'Request'
            if option53 == '04':
                dhcptype = 'Decline'
            if option53 == '05':
                dhcptype = 'ACK'
            if option53 == '06':
                dhcptype = 'NAK'
            if option53 == '07':
                dhcptype = 'Release'
            if option53 == '08':
                dhcptype = 'Inform'
                
        
############################# Iterates through all fingerprint tests #####################################
        for x in range(len(fingerprintList)):
            ##outer list, [ [[Fingerprint 1 test a], [Fingerprint 1 test b]] ,[[fingerprint 2 test a]] ]
            
            for y in range(len(fingerprintList[x])):
                
                ## [x][y][1] == name
                ## [x][y][2] == OS                      
                ## [x][y][3] == weight
                ## [x][y][4] == match type - exact, partial
                ## [x][y][5] == dhcp type - request, inform, release                        
                ## [x][y][6] == Options55 - parameter list
                ## [x][y][7] == Options - 
                ## [x][y][8] == Vendor Code
                ## [x][y][9] == IP TTL

                
                ##[x][y][5] contains dhcp message type ie Request, Inform, Discover"
                ##We only want to check a fingerprint the corresponds to the same DHCP type
                ##if (dhcptype and fingerprintList[x][y][5] != dhcptype and fingerprintList[x][y][5] != 'Any'):
                if (fingerprintList[x][y][5] != dhcptype and fingerprintList[x][y][5] != 'Any'):
                    continue            
                    
                ##look for a Options Param List, means != None       
                if fingerprintList[x][y][6] != None:
                    ##Remove the Commas and set to hex, to allow for comparison against fingerprint
                    ##[x][y][6] contains the dhcpoptions 55 param list
                    newString = removeCommasSetToHex(fingerprintList[x][y][6])

                    if option55 != None:
                        search55 = newString.find(option55)
                    else: search55 = -1

                    if option50 != None:                        
                        search50 = newString.find(option50)
                    else: search50 = -1

                    if option12 != None:                        
                        search12 = newString.find(option12)
                    else: search12 = -1

                    #Add up scores, for multiple hits on a fingerprint
                    if search55 != -1:
                        weight += int(fingerprintList[x][y][3])
                        #hitList.append([fingerprintList[x][y][1], weight])
                    
                    if search50 != -1:
                        weight += int(fingerprintList[x][y][3])
                        #hitList.append([fingerprintList[x][y][1], weight])
                        
                    if search12 != -1:
			if (fingerprintList[x][y][3] == 'NoneType') or           (fingerprintList[x][y][3] == 'int'):
			   print 'search12 Error'
			else:
                           weight += int(fingerprintList[x][y][3])
                        #hitList.append([fingerprintList[x][y][1], weight])

                if fingerprintList[x][y][8] != None:
                    ##We only want to check a fingerprint that matches the DHCP vendor code
                    if option60 != -1 and option60 != None:
                        search60 = fingerprintList[x][y][8].find(option60)
                    else: search60 = -1

                    if search60 != -1:
                         weight += int(fingerprintList[x][y][3])
                         #hitList.append([fingerprintList[x][y][1], weight])

            
            if weight > 0:
                hitList.append([fingerprintList[x][y][1],weight])
            weight = 0    

        return hitList
        
        
## Parses the list of DHCP.opts field from a DHCP packet
def dhcpMsgHasOption(listofoptions, optionnumber):
    for x in range(len(listofoptions)):
        try:
            result = optionnumber in listofoptions[x]
        except ValueError:
            pass
        if result:
            ##The list of options are stored as tuples, in a list...
            ##ie - [(53,'\x03'),(50, 'more stuff'),...
            ##print listofoptions[x]
            return listofoptions[x][1]

##Takes a packet and checks to see if it is DHCP, and then parses the DHCP fields   
def dhcpParse(IncomingPacket):

    pcapData = IncomingPacket
    sourceMAC = None
    packetCount = 0
    packetList = []
    
    #Read through packets in pcap, must be plain pcap format, not pcap-ng
    #try to grab a DHCP packet
    try:
        ether = ethernet.Ethernet(pcapData)
        ip = ether.data
        udp = ip.data
        dhcpDATA = udp.data
        dhcp1 = dhcp.DHCP(dhcpDATA)
	##MAC address is too long, then the packet is garbage
	if len(dhcp1.chaddr.encode('hex')) != int(12):
		return
    #Not a DHCP packet
    except NeedData:
        return
    #Not a DHCP packet
    except AttributeError:
        return
    #Not a DHCP packet
    except TypeError:
        return
    #If we get this far it's a DHCP packet
    packetList.append(
                    [#packetCount
                    dhcp1.xid
                    ,dhcp1.chaddr
                    ,dhcp1.ciaddr
                    ,dhcp1.data
                    ,dhcp1.file
                    ,dhcp1.flags
                    ,dhcp1.giaddr
                    ,dhcp1.hln
                    ,dhcp1.hops
                    ,dhcp1.hrd
                    ,dhcp1.magic
                    ,dhcp1.op
                    ,dhcp1.opts
                    ,dhcp1.secs
                    ,dhcp1.siaddr
                    ,dhcp1.sname
                    ,dhcp1
		    ,dhcp1.yiaddr])
    packetCount += 1
    sourceMAC = dhcp1.chaddr.encode('hex')
    #print sourceMAC
#    print '############################## DHCP ##########################################'
#    print "chaddr " + dhcp1.chaddr.encode('hex') + '\n'
#    print "ciaddr " + str(dhcp1.ciaddr) + '\n'
#    print "data " + dhcp1.data.encode('hex') + '\n'
#    print "file " + dhcp1.file.encode('hex') + '\n'
#    print "flags " + str(dhcp1.flags) + '\n'
#    print "giaddr " + str(dhcp1.giaddr) + '\n'
#    print "hln " + str(dhcp1.hln) + '\n'
#    print "hops " + str(dhcp1.hops) + '\n'
#    print "hrd " + str(dhcp1.hrd) + '\n'
#    print "magic " + str(dhcp1.magic) + '\n'
#    print "op " + str(dhcp1.op) + '\n'
#    print "opts " + repr(dhcp1.opts) + '\n'
#    print (dhcp1.opts[3][1]).encode('hex') 
#    print type(dhcp1.opts[3][1])
#    print "secs " + str(dhcp1.secs) + '\n'
#    print "siaddr " + str(dhcp1.siaddr) + '\n'
#    print "sname " + dhcp1.sname.encode('hex') + '\n'
#    print "xid " + str(dhcp1.xid) + '\n'
#    print "yiaddr " + str(dhcp1.yiaddr) + '\n'
#    print "DHCP - raw datagram dump\n" + repr(dhcp1) + '\n'

# print just whats in option 12 i.e. the host name
     
    return sourceMAC, packetList
##END dhcpParse()

##Parses XML from the startTag, and endTag, returns the start & end indexes of the resulting string
def parse(startTag, endTag, stringOfData):
    startIndex = stringOfData.find(startTag)
    endIndex = stringOfData.find(endTag,startIndex + len(startTag))
    if startIndex == -1:
        return startIndex, endIndex
    else:
        startIndex += len(startTag)
        return startIndex, endIndex
## end parse()


## Parses the XML fingerprint dhcptoption text to remove the commas, and set to hex
## This is needed because the incoming DHCP packet is hex
## A comparison is made against the fingerprint, and the DHCP field
def removeCommasSetToHex(instring):
    ## remove commas
    partedString = instring.split(",")
    ## need to change each string in the list to an int
    partedString = [int(a) for a in partedString]
    ## need to change from int to hex
    partedString = [hex(a) for a in partedString]
    ## when changed to hex, it is changed to a string and prepends "0x" to each digit
    ## remove each instance of "0x"
    for item in range(len(partedString)):
        if len(partedString[item]) == 3:
            partedString[item] = (partedString[item].replace('x',""))
        if len(partedString[item]) == 4:
            partedString[item] = (partedString[item].replace('0x',""))
    newString = "".join(partedString)
    return newString

##Parses the XML and returns a list of fingerprints
def createFingerPrintList(PathToTheXMLFile):

    #xmlfile = open(PathToTheXMLFile,'r')
    xmlfile = open(r'/ryu/ryu/app/Mid/fingerprint.xml','r')
    xml = xmlfile.read()        #place entire xml file into memory, as a string
    xmlfile.close()
    
    fingerprint = ''            #used to store xml string of one fingerprint
    fingerprintcounter = 0      #used as list index
    fingerprintStartIndex = 0
    fingerprintEndIndex = 0
    testStartIndex = 0
    testEndIndex = 0
    startIndex = 0
    endIndex = 0
    
    ######## TAGS & Search Strings ###########
    nameStart = 'name="'
    nameEnd = '"'
    osStart = 'os_name="'
    osEnd = '"'
    dhcpTestStart = '<dhcp_tests>'
    dhcpTestEnd = '</dhcp_tests>'
    testStart = '<test '
    testEnd = '/>'
    weightStart = 'weight="'
    weightEnd = '"'
    matchtypeStart = 'matchtype="'
    matchtypeEnd = '"'
    dhcptypeStart = 'dhcptype="' 
    dhcptypeEnd = '"'
    dhcpoptions55Start = 'dhcpoption55="'
    dhcpoptions55End = '"'
    dhcpoptionsStart = 'dhcpoptions="'
    dhcpoptionsEnd = '"'
    dhcpvendorStart = 'dhcpvendorcode="'
    dhcpvendorEnd = '"'
    ipttlStart = 'ipttl="'
    ipttlEnd = '"'
    fingerprintStart = '<fingerprint '
    fingerprintEnd = '</fingerprint>'
    fingerprintList = []

    #read one fingerprint at a time
    while fingerprintStartIndex < len(xml):
        fingerprintStartIndex = xml.find(fingerprintStart,fingerprintStartIndex,len(xml))
        fingerprintEndIndex = xml.find(fingerprintEnd,fingerprintStartIndex,len(xml))
        fingerprint = xml[fingerprintStartIndex+len(fingerprintStart):fingerprintEndIndex]   

        #once '<fingerprint ' tag isn't found, time to quit
        if fingerprintStartIndex != -1:
            #update counter to search for next fingerprint after the while loop completes an iteration
            fingerprintStartIndex = fingerprintEndIndex + 1

            #Parse for Item/Product Name
            startIndex, endIndex = parse(nameStart,nameEnd,fingerprint)
            name = fingerprint[startIndex:endIndex]
            if name == '':
                name = None
            
            #Parse for OS name
            startIndex, endIndex = parse(osStart,osEnd,fingerprint)
            os = fingerprint[startIndex:endIndex]
            if os == '':
                os = None

            #Parse for block of DHCP Tests
            startIndex, endIndex = parse(dhcpTestStart,dhcpTestEnd,fingerprint)
            if startIndex != -1:
                dhcpTest = fingerprint[startIndex:endIndex]

            #This should never happen...
            else:
                dhcpTest = None

            #Count the number of tests in each fingerprint
            counter = dhcpTest.count(testStart)
            fingerprintList.append([])
            #Parse each test into respective fields, place into list

            for i in range(counter):
                testStartIndex = fingerprint.find(testStart,testStartIndex) + len(testStart)
                testEndIndex = fingerprint.find(testEnd,testStartIndex)
                test = fingerprint[testStartIndex:testEndIndex]

                #Parse for the weight of a test
                startIndex, endIndex = parse(weightStart,weightEnd,test)
                if startIndex != -1:
                    weight = test[startIndex:endIndex]
                else:
                    weight = None

                #Parse for the Match Type of a test
                startIndex, endIndex = parse(matchtypeStart,matchtypeEnd,test)
                if startIndex != -1:
                    matchtype = test[startIndex:endIndex]
                else:
                    matchtype = None

                #Parse for DHCP Type
                startIndex, endIndex = parse(dhcptypeStart,dhcptypeEnd,test)
                if startIndex != -1:
                    dhcptype = test[startIndex:endIndex]
                else:
                    dhcptype = None

                #Parse for DHCP 55 Options
                startIndex, endIndex = parse(dhcpoptions55Start,dhcpoptions55End,test)
                if startIndex != -1:
                    dhcpoption55 = test[startIndex:endIndex]
                    ### removes commas from string, this method is deprecated in Python 3.x
                    #dhcpoption55 = dhcpoption55.translate(None, ',')
                else:
                    dhcpoption55 = None

                #Parse for DHCP Options
                startIndex, endIndex = parse(dhcpoptionsStart,dhcpoptionsEnd,test)
                if startIndex != -1:
                    dhcpoption = test[startIndex:endIndex]
                    ### removes commas from string, this method is deprecated in Python 3.x
                    #dhcpoption = dhcpoption.translate(None, ',')                    
                else:
                    dhcpoption = None

                #Parse for DHCP Vendor Code
                startIndex, endIndex = parse(dhcpvendorStart,dhcpvendorEnd,test)
                if startIndex != -1:
                    dhcpvendorcode = test[startIndex:endIndex]
                else:
                    dhcpvendorcode = None

                #Parse for IP Time-To-Live
                startIndex, endIndex = parse(ipttlStart,ipttlEnd,test)
                if startIndex != -1:
                    ipttlcode = test[startIndex:endIndex]
                else:
                    ipttlcode = None

                ##Fix DHCP Message Options and DHCP 55 Options
                
                fingerprintList[fingerprintcounter].append([fingerprintcounter,name,os,weight,matchtype,dhcptype,dhcpoption55,dhcpoption,dhcpvendorcode,ipttlcode])

                #fingerprintList is stored conceptually as:
                #fingerprintList[
                # [[1,name,os,weight,matchtype,dhcptype,dhcpoption55,dhcpoption,dhcpvendorcode,ipttlcode],[1,name,os,weight,matchtype,dhcptype,dhcpoption55,dhcpoption,dhcpvendorcode,ipttlcode]]
                # [[2,"1st set of Test fields"],....[2,"Nth set of Test fields"]]
                # .   
                # [[N,...]]
                #               ]

                testStartIndex = testEndIndex + 1
                ################## END LOOP
                
            fingerprintcounter += 1
            #must reset where the testStartIndex begins for the next fingerprint iteration, b/c there is a set of tests
            testStartIndex = 0
            
        else:
            break

    return fingerprintList
    ##END createFingerPrintList()

#Converts hexadecimal representation of MAC address to string type "AA:BB:CC:DD:EE:FF"
def getMACADD(mac):
    #print mac
    try:
        temp = mac.replace(":", "").replace("-", "").replace(".", "").upper()
	if len(str(mac)) != 12:
	   print 'MAC address error'
	else:
	   return temp[:2] + ":" + ":".join([temp[i] + temp[i+1] for i in range(2,12,2)])
    except:
	pass
#Convert DPID to Location
def DPIDToLocation(dpidflow):
	location = None
	if dpidflow=='0x12c59e5107640':
		location = '1 (Chicago)'
	elif dpidflow=='0x1c4346b94a200':
		location = '2 (Sunnyale)'
	elif dpidflow=='0x12c59e51016c0':
		location = '3 (Los Angeles)'
	elif dpidflow=='0x1c4346b99dc00':
		location = '4 (Salt Lake City)'
	elif dpidflow=='0x1c4346b946200':
		location = '5 (Denver)'
	elif dpidflow=='0x1c4346b971ec0':
		location = '6 (El Paso)'
	elif dpidflow=='0x1f0921c220e80':
		location = '8 (Cleveland)'
	elif dpidflow=='0x1c4346b98a200':
		location = '9 (Washington DC)'
	elif dpidflow=='0x1c4346b972a80':
		location = '10 (Atlanta)'
	elif dpidflow=='0x1f0921c226e80':
		location = '11 (Kansas City)'
	elif dpidflow=='0x140a8f0d12bc0':
		location = '12 (Seattle)'
	elif dpidflow=='0x1f0921c219d40':
		location = '13 (Houston)'
	elif dpidflow=='0x1f0921c225480':
		location = '14 (Nashville)'
        return location

#This function runs everytime when the controller recieves a packet
class getPacketDHCP(app_manager.RyuApp):

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_hander(self, ev):
        global fingerprintList
        printMAC = None
        sourceMAC = None
        parsedDHCPpacket = None
        pkt = ev.msg.data
	
        #tmp = dhcpParse(pkt)
	#print tmp
	#DHCP ID Location in each packet, convert to hex then to location	
	dpidflow = hex(ev.msg.datapath.id)
	#print dpidflow
        try:
            sourceMAC, parsedDHCPpacket = dhcpParse(pkt)
            #print sourceMAC
	    #print parsedDHCPpacket[0][17]
        except TypeError as e:
            return
        #might be able to delete this if statement, should be taken care of by try, except block
        if  sourceMAC != None or parsedDHCPpacket != None:
            #if parsedDHCPpacket != None:
            hitlist = compare(fingerprintList, parsedDHCPpacket)

	#search through the parsedDHCPpacket to find the host name, dhcp type, and vendor class
	    Hostname = dhcpMsgHasOption(parsedDHCPpacket[0][12],12)
	    option53 = dhcpMsgHasOption(parsedDHCPpacket[0][12],53)
	    option60 = dhcpMsgHasOption(parsedDHCPpacket[0][12],60)
	     ## convert the dhcp type 
            dhcptype = None
            if option53:
               if option53 == '\x01':
                   dhcptype = 'Discover'
               if option53 == '\x02':
                   dhcptype = 'Offer'    
               if option53 == '\x03':
                   dhcptype = 'Request'
               if option53 == '\x04':
                   dhcptype = 'Decline'
               if option53 == '\x05':
                   dhcptype = 'ACK'
               if option53 == '\x06':
                   dhcptype = 'NAK'
               if option53 == '\x07':
                   dhcptype = 'Release'
               if option53 == '\x08':
                   dhcptype = 'Inform'

	    #Source IP Address, converts ASCII Value to IP format
	    #print parsedDHCPpacket

	    #Client IP Address
	    if parsedDHCPpacket[0][2] != 0:
		sourceIP = hex(parsedDHCPpacket[0][2])
		sourceIP = hexToIP(sourceIP)
	    #Check "Your IP Address"
	    elif parsedDHCPpacket[0][17] != 0:
		sourceIP = hex(parsedDHCPpacket[0][17])
		sourceIP = hexToIP(sourceIP)

	    #Option 50 has the IP address
	    elif dhcpMsgHasOption(parsedDHCPpacket[0][12],50) != None:
		sourceIP = dhcpMsgHasOption(parsedDHCPpacket[0][12],50)
		sourceIP = map(ord, sourceIP)
		sourceIP = '.'.join(str(x) for x in sourceIP)
	    else:
		sourceIP = None
	   #Collect MAC, Location, OS, and Port, add to cookie
	    MAC = getMACADD(sourceMAC)
	    Location = DPIDToLocation(dpidflow)
 	    port = ev.msg.in_port
	    #print port
	    cookie = hash(str(sourceMAC) + str(sourceIP) + str(dhcptype))
	    #print cookie 
	    #print cookiejar
            #Look to see if the cookie already exists
	    #print only if the location is same as the original
            try:
                MACfingerprintLIST[sourceMAC]
		if cookie not in cookiejar:
                    print '\n' + "This fingerprint already exists"
                    print "Source MAC: {}".format(MAC)
		    print "IP Address: {}".format(sourceIP)
		    print "Location  : {}".format(Location)
		    print "Host name : {}".format(Hostname)
		    print "DHCP Type : {}".format(dhcptype)
		    print "Option 60 : {}".format(option60)
                    print "Fingerprint: %s" % MACfingerprintLIST[sourceMAC]
                    out_string= "Fingerprint already Exists"
                    f= open('fingerprint_log.txt', 'w')
                    f.write(out_string)
                    f.close()
                #If a fingerprint exists, but doesn't match a new one...
		#again, only print if the location is same as the original
                elif MACfingerprintLIST[sourceMAC] != hitlist:
                    print '\n' + "The OS has changed. The old fingerprint was:"
                    print "Source MAC: {}".format(MAC)
		    print "IP Address: {}".format(sourceIP)
		    print "Location  : {}".format(DPIDToLocation(dpidflow))
		    print "Host name : {}".format(Hostname)
		    print "DHCP Type : {}".format(dhcptype)
                    print "Fingerprint: %s" % MACfingerprintLIST[sourceMAC]
                    print "The new fingerprint is:"
                    print hitlist
                    out_string= "Fingerprint Changed!"
                    f= open('fingerprint_log.txt', 'w')
                    f.write(out_string)
                    f.close()
                    #r = requests.get("http://0.0.0.0:8080/"+getMACADD(sourceMAC)+"/disable")
                    #print r.text                   
            #If the fingerprint doesn't exist we add it
            except KeyError:
                MACfingerprintLIST[sourceMAC] = hitlist
		cookiejar.append(cookie)
                print '\n' + "Added MAC + DHCP fingerprint"
                print "Source MAC: {}".format(MAC)
		print "IP Address: {}".format(sourceIP)
		print "Location  : {}".format(DPIDToLocation(dpidflow))
                print "Host name : {}".format(Hostname)
                print "DHCP Type : {}".format(dhcptype)
		print "Option 60 : {}".format(option60)
                print "Fingerprint: %s" % MACfingerprintLIST[sourceMAC]
                out_string= "New Fingerprint"
                f= open('fingerprint_log.txt', 'w')
                f.write(out_string)
                f.close()
        else:
            print "Not a DHCP packet"
        

fingerprintList = createFingerPrintList(test)

