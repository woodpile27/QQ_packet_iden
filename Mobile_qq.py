from scapy.all import *
import re

def dump(x):
    x = str(x)
    return ["%#04x" % ord(x) for x in x]

def match_mobile_qq(pkt):
    if TCP in pkt and Raw in pkt:
        hex_pkt = dump(pkt[Raw])
        try:
            if hex_pkt[4] == hex_pkt[5] == hex_pkt[6] == '0x00' and hex_pkt[7] in ['0x0a', '0x0b'] and hex_pkt[8] in ['0x01','0x02']:
                return get_mobile_qq_num(pkt)
            else:
                return None
        except:
            return None

def get_mobile_qq_num(pkt):        
    hex_pkt = dump(pkt[Raw])
    # qq_num maxlen is 12
    # server:14000 -->  client   !may not 14000
    #if hex_pkt == '0x00':
    if pkt.sport == 14000:
        start = 14
        num_len = int(hex_pkt[start-1], 16) - 4
        end = start + num_len
        qq_num = ''.join([chr(int(i, 16)) for i in hex_pkt[start:end]])
    # client --> server:14000
    #else:
    elif pkt.dport == 14000:
        start = 18
        num_len = int(hex_pkt[start-1], 16) - 4
        end = start + num_len
        qq_num =  ''.join([chr(int(i, 16)) for i in hex_pkt[start:end]])
    pattern = re.compile('(\d{5,%d})' % num_len)
    try:
        qq_num = re.match(pattern, qq_num).group()
        return qq_num
    except Exception,e:
        return None # num in pkt but not usual

