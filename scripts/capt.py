import os
import pyshark
import parse
import binascii

capture = pyshark.FileCapture('PASSWD.pcap', 
                              use_json=True, 
                              include_raw=True,
                              override_prefs={'ssl.keylog_file': os.path.abspath('keys.keylog')},
                              debug=True)

# filter: http only 
def get_http(capture):
    http_packets = []
    for packet in capture:
        if packet.highest_layer == "HTTP2_RAW":
            http_packets.append(packet)

    return http_packets

def aggregate_pbufs():
    return 0

def get_headers1(pack):
    return pack.layers[4].stream[0].header 

def get_headers2(pack):
    return pack.layers[4].stream.header 

def try_get_content_type_with_getter(p, head_getter):
    try:
        headers = head_getter(p)
        for h in headers:
            if h.header.name == "content-type":
                return h.header.value

        return "" 
    except Exception:
        return ""

def try_get_content_type(p):
    r1 = try_get_content_type_with_getter(p, get_headers1)
    if r1 != "":
        return r1
    else:
        return try_get_content_type_with_getter(p, get_headers2)

# content-encoded_entity_body_(gzip)
def try_get_protobuf_data_fst(p):
    try:
        data = p.layers[4].stream
        # data = getattr(data, "content-encoded_entity_body_(gzip)").data_raw[0]
        data = data.data_raw[0]
        return data
    except Exception:
        return ""

def try_get_protobuf_data_snd(p):
    try:
        data = p.layers[4].stream
        data = getattr(data, "content-encoded_entity_body_(gzip)").data_raw[0]
        return data
    except Exception:
        return ""

def try_get_protobuf(p):
    r1 = try_get_protobuf_data_fst(p)
    if r1 != "":
        return r1
    else: 
        return try_get_protobuf_data_snd(p)

def get_all_protobuf(capture):
    http_packs = get_http(capture)
    result = []
    
    for i in range(0, len(http_packs)):
        ct = try_get_content_type(http_packs[i])
        if "application/x-protobuf" in ct:
            pbuf_list = []
            for j in range(i + 1, len(http_packs)):
                pbuf = try_get_protobuf(http_packs[j])
                if (len(pbuf) > 0):
                    pbuf_list.append(pbuf)
                    if j == len(http_packs) - 1:
                        result.append(pbuf_list) 
                else:
                    result.append(pbuf_list) 
                    break
                i = i + 1
    
        o = 0
    return result

http_packets = get_http(capture)

protobufs = get_all_protobuf(capture)

p = protobufs[1][0]

proto_byte = bytearray.fromhex(p)

def byte_to_string(bytes):
    acc = []
    for i in range(len(bytes)):
        acc.append(chr(bytes[i]))

    return acc

def convert(s):
    str1 = ""

    return (str1.join(s))

characters = byte_to_string(proto_byte)
data = convert(characters)
res = parse.decode_protobuf_array2(data)
print(res[7])

#a = try_get_content_type(pbuf0)

#b = get_headers(pbuf0)
#res = getattr(res, "0").header

#pbuf = http_packets[10]
#data = pbuf.layers[4].stream
#data = getattr(data, "content-encoded_entity_body_(gzip)").data_raw[0]
#t = 1