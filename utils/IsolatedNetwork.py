import pexpect
import argparse

password = "ccw"
username = "manager"

parser = argparse.ArgumentParser(description='Toggle topologies')
parser.add_argument("--on", dest="on", action="store_true")
parser.add_argument("--off", dest="off", action="store_true")
parser.add_argument("--reset", dest="restart", action="store_true")
arg = parser.parse_args()

disable_ports = {"10.10.0.1":[3], "10.10.0.2":[1,2], "10.10.0.3":[1,3], "10.10.0.4":[3],\
		"10.10.0.5":[], "10.10.0.6":[3], "10.10.0.8":[], "10.10.0.9":[], "10.10.0.10":[],\
		"10.10.0.11":[1,2], "10.10.0.12":[], "10.10.0.13":[1,2,4], "10.10.0.14":[1,2]}

for hostname in disable_ports:
    s = pexpect.spawn("ssh %s@%s" %(username,hostname))
    s.expect(".*assword")
    s.sendline(password)
    s.expect("Press any key to continue")
    s.sendline("\r")
    s.sendline("config")
   
    if arg.on:
        for n in range(1,25):
            print("Enabling and clearing port " + `n` + " on " + hostname)
            s.sendline("interface ethernet " + `n` + " enable")
	    s.sendline("clear statistics " + `n`)

        for port in disable_ports[hostname]:
            print("Disabling port " + `port` + " on " + hostname)
            s.sendline("interface ethernet " + `port` + " disable")
    elif arg.off:
        for n in disable_ports[hostname]:
            print("Enabling port " + `n` + " on " + hostname)
            s.sendline("interface ethernet " + `n` + " enable")

    s.sendline("save")
    s.sendline("logo")
    s.sendline("y")

 


