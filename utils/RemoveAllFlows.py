import os
switches = [1,2,3,4,5,6,8,9,10,11,12,13,14]

for switch in switches:
    print("Deleting flows on {}".format(switch))
    os.system("dpctl del-flows tcp:10.10.0.{}:6655".format(switch))     
