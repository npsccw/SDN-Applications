############### Miscellaneous Functions #######################
def dot_to_dec(ip_string):
        ip = map(int,ip_string.split("."))
        return (16777216 * ip[0]) + (65536 * ip[1]) + (256 * ip[2]) + ip[3]

def hex_to_ip(h):
    return `int(h[2:3],16)` + '.' + \
            `int(h[3:5],16)` + '.' + \
            `int(h[5:7],16)` + '.' + `int(h[7:9],16)`

def hex_to_mac(mac):
    try:
        temp = mac.replace(":", "").replace("-", "").replace(".", "").upper()
        if len(str(temp)) != 12:
            print("MAC address error")
        else:
            return temp[:2] + ":" + ":".join([temp[i] + temp[i+1] for i in range(2,12,2)])
    except:
        print("Conversion Error")



############### NPS CCW Network Specific Functions #############
def DPIDToLocation(dpidflow):
    location = None
    if dpidflow=='0x12c59e5107640':
        location = '1'
    elif dpidflow=='0x1c4346b94a200':
        location = '2'
    elif dpidflow=='0x12c59e51016c0':
        location = '3'
    elif dpidflow=='0x1c4346b99dc00':
        location = '4'
    elif dpidflow=='0x1c4346b946200':
        location = '5'
    elif dpidflow=='0x1c4346b971ec0':
        location = '6'
    elif dpidflow=='0x1f0921c220e80':
        location = '8'
    elif dpidflow=='0x1c4346b98a200':
        location = '9'
    elif dpidflow=='0x1c4346b972a80':
        location = '10'
    elif dpidflow=='0x1f0921c226e80':
        location = '11'
    elif dpidflow=='0x140a8f0d12bc0':
        location = '12'
    elif dpidflow=='0x1f0921c219d40':
        location = '13'
    elif dpidflow=='0x1f0921c225480':
        location = '14'
    return location