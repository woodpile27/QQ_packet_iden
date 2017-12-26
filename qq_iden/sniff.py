from scapy.all import *
import re
import time
import threading
import IPy
import redis
import pymongo
from config import *


REDIS = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
mongo_client = pymongo.MongoClient(MONGO_URI)
mongodb = mongo_client[MONGO_DB]


def sniff_iden():
    #sniff(iface='at0', prn=save_to_redis, filter='wlan[0]==0x88')
    sniff(iface=IFACE_NAME, prn=save_to_redis, filter='tcp or udp')


def save_to_redis(pkt):
    data = str(pkt)
    try:
        REDIS.rpush("wifi_iden", data)
        print 'save to redis successful'
    except Exception, e:
        print e
        print 'save to redis failed'


def get_from_redis():
    while True:
        try:
            data = REDIS.lpop("wifi_iden")
            if data:
                #pkt = RadioTap(data)
                pkt = Ether(data)
                parse(pkt)
            else:
                print 'wifi_iden is empty, wait a second'
                time.sleep(1)
        except Exception, e:
            print e
            print 'get from redis error'


def parse(pkt):
    qq_num = ''
    mac, from_server = get_mac(pkt)
    if pkt.haslayer(UDP) and pkt.haslayer(Raw):
        qq_num = PC_qq(pkt)
    elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
        qq_num = Mobile_qq(pkt, from_server)
    else:
        pass
    if qq_num:
        data = {
                'mac': mac, 
                'QQ_num': qq_num
                }
        save_to_mongo(data)


def get_mac(pkt):
    if pkt.haslayer(Ether):
        src_ip = IPy.IP(pkt[IP].src)
        if src_ip.iptype() == 'PRIVATE':
            mac = pkt.src
            from_server = False
        else:
            mac = pkt.dst
            from_server = True
    elif pkt.haslayer(Dot11):
        # from-DS
        if bin(pkt.FCfield) == '0':
            mac = pkt[Dot11].addr1
            from_server = True
        # to-DS
        else:
            mac = pkt[Dot11].addr2
            from_server = False
    return mac, from_server


def dump(x):
    x = str(x)
    return ["%#04x" % ord(x) for x in x]


def PC_qq(pkt):
    raw_dump = dump(pkt[Raw])
    if raw_dump[0] == '0x02' and raw_dump[-1] == '0x03':
        qq_num = int('0x' + ''.join([x[2:4] for x in raw_dump[7:11]]), 16)
        return qq_num
    else:
        return None


def Mobile_qq(pkt, from_server):
    raw_dump = dump(pkt[Raw])
    # raw_dump[7] in ['0x0a', '0x0b', 0x0d']
    if raw_dump[4] == raw_dump[5] == raw_dump[6] == '0x00' and raw_dump[8] in ['0x01', '0x02']:
        if from_server:
            start = 14
            num_len = int(raw_dump[start-1], 16) - 4
            end = start + num_len
            qq_num = ''.join([chr(int(i, 16)) for i in raw_dump[start:end]])
        else:
            start = 18
            num_len = int(raw_dump[start-1], 16) - 4
            end = start + num_len
            qq_num = ''.join([chr(int(i, 16)) for i in raw_dump[start:end]])
        pattern = re.compile('(\d{%d})' % num_len)
        try:
            qq_num = re.match(pattern, qq_num).group()
            return qq_num
        except Exception:
            return None
    else:
        return None

    
def save_to_mongo(data):
    try:
        if mongodb['qq_iden'].update({'mac': data['mac']},{'$addToSet': {'qq_num': data['QQ_num']}}, upsert=True):
            print 'save to mongodb successful'
    except Exception, e:
        print e
        print 'save to mongodb failed'


if __name__ == '__main__':
    threading.Thread(target=sniff_iden).start()
    threading.Thread(target=get_from_redis).start()
