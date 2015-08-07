import nmap
from paramiko import SSHClient, AutoAddPolicy, util
from scp import SCPClient
import argparse

def online():
    nm = nmap.PortScanner()
    nm.scan('10.10.13.2-250', arguments="-F")
    print(nm.all_hosts())
    """
    with open('activeIPs', 'w') as f:
        for ip in nm.all_hosts():
	    f.write(str(ip) + "\n")
	f.flush()
    """
    return nm.all_hosts()

def broadcast(file, hosts):
    client = SSHClient()
    util.log_to_file("this.log")
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())
    for ip in hosts:
	try:
	    print("Logging into: " + ip)
            client.connect(hostname=ip, username="pi", password="pi") 
	    scp = SCPClient(client.get_transport())
	    scp.put(file)
	    scp.close()
            client.close()
        except:
	    print(ip + " is being stubborn")
   	    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mass send a file.")
    parser.add_argument("-f", "--file", dest="file", help="Enter the file to broadcast")
    args = parser.parse_args()

    print("Broadcasting file: " + args.file)
    online()
#   broadcast(args.file, online())
    print("Done!")  
