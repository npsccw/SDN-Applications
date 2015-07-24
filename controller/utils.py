############### Miscellaneous Functions #######################
def dot_to_dec(ip_string):
        ip = map(int,ip_string.split("."))
        return (16777216 * ip[0]) + (65536 * ip[1]) + (256 * ip[2]) + ip[3]
