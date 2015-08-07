"""
Helper class for the fingerprint application
There are better ways of parsing the packet
that should be looked into.
"""
from dpkt import *
import requests
import hashlib
from cassandra.cluster import Cluster
from datetime import datetime
dhcp_types = { '\x01': 'Discover', '\x02': 'Offer',\
                            '\x03':'Request', '\x04':'Decline',\
                            '\x05':'ACK', '\x06':'NAK',\
                            '\x07':'Release', '\x08': 'Inform'}
dhcp_types1 = {'01': 'Discover', '02': 'Offer',\
                            '03':'Request', '04':'Decline',\
                            '05':'ACK', '06':'NAK',\
                            '07':'Release', '08': 'Inform'}
def compare(list_of_fingerprints, parsedDHCP):
    """
    Takes a DHCP packet that was parsed for
    ___ and returns a matching against a 
    fingerprint database
    """
    hitlist = []
    option_list = parsedDHCP[12]
    option53, option50, option12, option55, option60 = \
                [get_dhcp_option_value(option_list, i) for i in [53, 50, 12, 55, 60]]
    dhcptype = dhcp_types1[option53.encode('hex')]

    for x in range(len(list_of_fingerprints)):
        for y in range(len(list_of_fingerprints[x])):
            if list_of_fingerprints[x][y][5] not in [dhcptype, 'Any']:
                continue

            if list_of_fingerprints[x][y][6]:
                option_string = refine_text_string(list_of_fingerprints[x][y][6])
		weight = 0
                if option55:
                    if option_string.find(option55.encode('hex')) != -1:
			weight += int(list_of_fingerprints[x][y][3])
                if option50:
                    if option_string.find(option50.encode('hex')) != -1:
			weight += int(list_of_fingerprints[x][y][3])
                if option12:
                    if option_string.find(option12) != -1:
			weight += int(list_of_fingerprints[x][y][3])

            if list_of_fingerprints[x][y][8]:
                if option60:
                    if list_of_fingerprints[x][y][8].find(option60) != -1:
                        weight += int(list_of_fingerprints[x][y][3])   

            if weight:
                hitlist.append([list_of_fingerprints[x][y][1], weight])
    return hitlist


def get_dhcp_option_value(list_of_options, option_number):
    """
    Takes a list of DHCP options present in a packet
    and then tries to grab the value associated with 
    that option.
    """
    for x in range(len(list_of_options)):
        if list_of_options[x][0] == option_number:
            return list_of_options[x][1]


def dhcp_parse(pkt):
    """
    Attempts to parse a packet for dhcp fields
    """
    try:
        ether = ethernet.Ethernet(pkt)
        ip = ether.data
        udp = ip.data
        dhcp_data = dhcp.DHCP(udp.data)
        source_mac = dhcp_data.chaddr.encode('hex')
        if len(source_mac) != 12:
            #MAC address is too long, so packet is garbage
            return
    except AttributeError,TypeError:
        #Not a DHCP Packet
        return
    except NeedData:
	return
    packet_list = [dhcp_data.xid, dhcp_data.chaddr,\
                     dhcp_data.ciaddr, dhcp_data.data,\
                     dhcp_data.file, dhcp_data.flags,\
                     dhcp_data.giaddr, dhcp_data.hln,\
                     dhcp_data.hops, dhcp_data.hrd,\
                     dhcp_data.magic, dhcp_data.op,\
                     dhcp_data.opts, dhcp_data.secs,\
                     dhcp_data.siaddr, dhcp_data.sname,\
                     dhcp_data.yiaddr, dhcp_data]
    return source_mac, packet_list

def xml_parse(startTag, endTag, data_string):
    """
    Searches a string for tags and returns the indices
    of those tags
    """
    startIndex = data_string.find(startTag)
    endIndex = data_string.find(endTag, startIndex + len(startTag))
    offset = 0
    if startIndex != -1:
        offset = len(startTag)
    return startIndex+offset, endIndex

def refine_text_string(text_string):
    """
    Removes commas, converts elements to hex,
    and then stiches back together in a string
    """
    text_list = text_string.split(",")
    hex_list = [hex(int(a)) for a in text_list]
    for i in range(len(hex_list)):
        if len(hex_list[i]) == 3:
            hex_list[i] = hex_list[i].replace('x', "")
        elif len(hex_list[i]) == 4:
            hex_list[i] = hex_list[i].replace('0x', "")
    return "".join(hex_list)

def check_mac(mac):
    """
    Checks the database to ensure no duplicates
    """
    cluster = Cluster()
    session = cluster.connect('fingerprints')
    cqlsh = "select * from fps2 where mac = '{0}'".format(mac)
    result = session.execute(cqlsh)
    if not result:
        print "new mac"
        return True

def createFingerPrintList(PathToTheXMLFile='fingerprint.xml'):
    """
    Converts an XML file into a list of Strings
    for further processing
    """
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
            startIndex, endIndex = xml_parse(nameStart,nameEnd,fingerprint)
            name = fingerprint[startIndex:endIndex]
            if name == '':
                name = None
            
            #Parse for OS name
            startIndex, endIndex = xml_parse(osStart,osEnd,fingerprint)
            os = fingerprint[startIndex:endIndex]
            if os == '':
                os = None

            #Parse for block of DHCP Tests
            startIndex, endIndex = xml_parse(dhcpTestStart,dhcpTestEnd,fingerprint)
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
                startIndex, endIndex = xml_parse(weightStart,weightEnd,test)
                if startIndex != -1:
                    weight = test[startIndex:endIndex]
                else:
                    weight = None

                #Parse for the Match Type of a test
                startIndex, endIndex = xml_parse(matchtypeStart,matchtypeEnd,test)
                if startIndex != -1:
                    matchtype = test[startIndex:endIndex]
                else:
                    matchtype = None

                #Parse for DHCP Type
                startIndex, endIndex = xml_parse(dhcptypeStart,dhcptypeEnd,test)
                if startIndex != -1:
                    dhcptype = test[startIndex:endIndex]
                else:
                    dhcptype = None

                #Parse for DHCP 55 Options
                startIndex, endIndex = xml_parse(dhcpoptions55Start,dhcpoptions55End,test)
                if startIndex != -1:
                    dhcpoption55 = test[startIndex:endIndex]
                    ### removes commas from string, this method is deprecated in Python 3.x
                    #dhcpoption55 = dhcpoption55.translate(None, ',')
                else:
                    dhcpoption55 = None

                #Parse for DHCP Options
                startIndex, endIndex = xml_parse(dhcpoptionsStart,dhcpoptionsEnd,test)
                if startIndex != -1:
                    dhcpoption = test[startIndex:endIndex]
                    ### removes commas from string, this method is deprecated in Python 3.x
                    #dhcpoption = dhcpoption.translate(None, ',')                    
                else:
                    dhcpoption = None

                #Parse for DHCP Vendor Code
                startIndex, endIndex = xml_parse(dhcpvendorStart,dhcpvendorEnd,test)
                if startIndex != -1:
                    dhcpvendorcode = test[startIndex:endIndex]
                else:
                    dhcpvendorcode = None

                #Parse for IP Time-To-Live
                startIndex, endIndex = xml_parse(ipttlStart,ipttlEnd,test)
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
