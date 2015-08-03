from pexpect import spawn

def map_switch_dpid():
    mapping = {}
    try:
	with open("ip_dpid_map", "r") as f:
	    lines = f.readlines()
	    for line in lines:
	        line = line.split("-")
	        mapping[line[1].strip()] = line[0]

    except:
	with open("switch_ips", "r") as f:
	    switches = f.readlines()

	with open("ip_dpid_map", "w") as f:
            for switch in switches:
                switch = switch.strip()
	        print("Logging into " + switch)
                if not switch:
                    continue
        
                s = spawn("ssh manager@" + switch)
        	i = s.expect(["Are you sure you want to continue connecting", ".*assword"])
		if i == 0:
    	    	    s.sendline("yes")
    	    	    i = s.expect(["Are you sure you want to continue connecting", ".*assword"])
		if i == 1:
            	    s.sendline("ccw")
        	    s.sendline("\r")
        	screen_line = s.readline()
        	screen_line = s.readline()
        	while screen_line != "\r\n":
            	    screen_line = s.readline()
        	    s.sendline("show openflow")
        	    screen_line = s.readline()
        	while "------" not in screen_line:
	    	    screen_line = s.readline()
        	screen_line = s.readline().split()
        	while screen_line[1] != "Up":
            	    screen_line = s.readline().split()
        	s.sendline("show openflow instance " + screen_line[0])
        	screen_line = s.readline().split()

        	while screen_line == [] or screen_line[0] != "Datapath":
            	    screen_line = s.readline().split()
            	while screen_line == []:
                    screen_line = s.readline().split() 
        	datapath_id = "0x" + screen_line[3][3:]
        	print(switch + "-" + datapath_id)
        	f.write(switch + "-" + datapath_id + "\n")
		mapping[datapath_id] = switch
		s.sendline("logo")
        	s.sendline("y")

    return mapping

#if __name__ == "__main__":
    #print(map_switch_dpid())

