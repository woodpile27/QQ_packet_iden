from scapy.all import *

def dump(x):
    x = str(x)
    return ["%02x" % ord(x) for x in x]  # remove 0x

def parse(pkt):
    commands = {
        "0x0001": "Log out" , 
        "0x0002": "Heart Message" ,
        "0x0004": "Update User information" ,
        "0x0005": "Search user" ,
        "0x0006": "Get User informationBroadcast" ,
        "0x0009": "Add friend no auth" ,
        "0x000a": "Delete user" ,
        "0x000b": "Add friend by auth" ,
        "0x000d": "Set status" ,
        "0x0012": "Confirmation of receiving message from server" ,    
        "0x0016": "Send message" ,
        "0x0017": "Receive message" ,
        "0x0018": "Retrieve information" ,
        "0x001a": "Reserved " ,
        "0x001c": "Delete Me" ,
        "0x001d": "Request KEY" ,
        "0x0021": "Cell Phone" ,
        "0x0022": "Log in" ,
        "0x0026": "Get friend list" ,
        "0x0027": "Get friend online" ,
        "0x0029": "Cell PHONE" ,
        "0x0030": "Operation on group" ,
        "0x0031": "Log in test" ,
        "0x003c": "Group name operation" ,
        "0x003d": "Upload group friend" ,
        "0x003e": "MEMO Operation" ,
        "0x0058": "Download group friend" ,
        "0x005c": "Get level" ,
        "0x0062": "Request login" ,
        "0x0065": "Request extra information" ,
        "0x0067": "Signature operation" ,
        "0x0080": "Receive system message" ,
        "0x0081": "Get status of friend" ,
        "0x00b5": "Get friend's status of group" ,
        "0x0000": "NULL" 
    }
    if pkt.haslayer(UDP) and pkt.haslayer(Raw):
        raw_dump = dump(pkt[Raw])
        if raw_dump[0] == '02' and raw_dump[-1] == '03':
            command = '0x' + raw_dump[3] + raw_dump[4]
            if command in commands:
                command_value = commands[command]
                qqnum = int('0x' + ''.join(raw_dump[7:11]), 16)
                print command_value
                print qqnum
                print '========'
            else:
                print 'qq udp but no num'
        else:
            print 'no'
    else:
        print 'no udp'

