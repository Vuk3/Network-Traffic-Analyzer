import base64


def extract_http_data(packet):
    data = {}
    if hasattr(packet.http, 'authorization'):
        if 'Basic' in packet.http.authorization:
            auth_info = packet.http.authorization.split('Basic ')[1]
            decoded_auth = base64.b64decode(auth_info).decode()
            data['HTTP Basic Auth'] = decoded_auth
    if hasattr(packet.http, 'host'):
        data['Host'] = packet.http.host
    if hasattr(packet.http, 'user_agent'):
        data['User Agent'] = packet.http.user_agent
    if hasattr(packet.http, 'request_uri'):
        data['Request URI'] = packet.http.request_uri
    if hasattr(packet.http, 'file_data'):
        data['Form Data'] = packet.http.file_data
    if hasattr(packet.http, 'cookie'):
        data['Cookie'] = packet.http.cookie
    if hasattr(packet.http, 'content_type'):
        data['Content Type'] = packet.http.content_type
    if hasattr(packet.http, 'response_code'):
        data['Response Code'] = packet.http.response_code
    if hasattr(packet.http, 'server'):
        data['Server'] = packet.http.server
    if hasattr(packet.http, 'referer'):
        data['Referer'] = packet.http.referer
    if hasattr(packet.http, 'accept_language'):
        data['Accept Language'] = packet.http.accept_language
    if hasattr(packet.http, 'accept_encoding'):
        data['Accept Encoding'] = packet.http.accept_encoding
    if hasattr(packet.http, 'content_length'):
        data['Content Length'] = packet.http.content_length
    return data

def extract_https_data(packet):
    data = {}
    if hasattr(packet.ssl, 'handshake_version'):
        data['SSL Version'] = packet.ssl.handshake_version
    if hasattr(packet.ssl, 'handshake_cipher_suite'):
        data['Cipher Suite'] = packet.ssl.handshake_cipher_suite
    if hasattr(packet.ssl, 'handshake_extensions_server_name'):
        data['Server Name'] = packet.ssl.handshake_extensions_server_name
    return data

def extract_dns_data(packet):
    data = {}
    if hasattr(packet.dns, 'qry_name'):
        data['DNS Query'] = packet.dns.qry_name
    if hasattr(packet.dns, 'a'):
        data['DNS Response'] = packet.dns.a
    if hasattr(packet.dns, 'qry_type'):
        data['Query Type'] = packet.dns.qry_type
    if hasattr(packet.dns, 'qry_class'):
        data['Query Class'] = packet.dns.qry_class
    return data

def extract_ftp_data(packet):
    data = {}
    if hasattr(packet.ftp, 'request'):
        data['FTP Request'] = packet.ftp.request
    if hasattr(packet.ftp, 'response'):
        data['FTP Response'] = packet.ftp.response
    if hasattr(packet.ftp, 'username'):
        data['Username'] = packet.ftp.username
    if hasattr(packet.ftp, 'password'):
        data['Password'] = packet.ftp.password
    return data

def extract_smtp_data(packet):
    data = {}
    if hasattr(packet.smtp, 'mail_from'):
        data['SMTP From'] = packet.smtp.mail_from
    if hasattr(packet.smtp, 'rcpt_to'):
        data['SMTP To'] = packet.smtp.rcpt_to
    if hasattr(packet.smtp, 'data'):
        data['SMTP Data'] = packet.smtp.data
    if hasattr(packet.smtp, 'subject'):
        data['Subject'] = packet.smtp.subject
    return data

def extract_arp_data(packet):
    data = {}
    if hasattr(packet.arp, 'src_proto_ipv4'):
        data['ARP Source IP'] = packet.arp.src_proto_ipv4
    if hasattr(packet.arp, 'dst_proto_ipv4'):
        data['ARP Destination IP'] = packet.arp.dst_proto_ipv4
    if hasattr(packet.arp, 'hw_src'):
        data['Hardware Source'] = packet.arp.hw_src
    if hasattr(packet.arp, 'hw_dst'):
        data['Hardware Destination'] = packet.arp.hw_dst
    if hasattr(packet.arp, 'opcode'):
        data['Opcode'] = packet.arp.opcode
    return data

def extract_icmp_data(packet):
    data = {}
    if hasattr(packet.icmp, 'type'):
        data['ICMP Type'] = packet.icmp.type
    if hasattr(packet.icmp, 'code'):
        data['ICMP Code'] = packet.icmp.code
    if hasattr(packet.icmp, 'seq'):
        data['Sequence'] = packet.icmp.seq
    if hasattr(packet.icmp, 'checksum'):
        data['Checksum'] = packet.icmp.checksum
    return data

def extract_ip_data(packet):
    data = {}
    if hasattr(packet.ip, 'src'):
        data['IP Source'] = packet.ip.src
    if hasattr(packet.ip, 'dst'):
        data['IP Destination'] = packet.ip.dst
    if hasattr(packet.ip, 'ttl'):
        data['TTL'] = packet.ip.ttl
    if hasattr(packet.ip, 'len'):
        data['IP Packet Length'] = packet.ip.len
    if hasattr(packet.ip, 'flags'):
        data['IP Flags'] = packet.ip.flags
    if hasattr(packet.ip, 'id'):
        data['IP ID'] = packet.ip.id
    if hasattr(packet.ip, 'tos'):
        data['Type of Service'] = packet.ip.tos
    if hasattr(packet.ip, 'proto'):
        data['Protocol'] = packet.ip.proto
    return data

def extract_ethernet_data(packet):
    data = {}
    if hasattr(packet.eth, 'src'):
        data['Ethernet Source'] = packet.eth.src
    if hasattr(packet.eth, 'dst'):
        data['Ethernet Destination'] = packet.eth.dst
    if hasattr(packet.eth, 'type'):
        data['Ethernet Type'] = packet.eth.type
    if hasattr(packet.eth, 'src_resolved'):
        data['Source Resolved'] = packet.eth.src_resolved
    if hasattr(packet.eth, 'dst_resolved'):
        data['Destination Resolved'] = packet.eth.dst_resolved
    return data

def extract_tcp_data(packet):
    data = {}
    if hasattr(packet.tcp, 'srcport'):
        data['TCP Source Port'] = packet.tcp.srcport
    if hasattr(packet.tcp, 'dstport'):
        data['TCP Destination Port'] = packet.tcp.dstport
    if hasattr(packet.tcp, 'seq'):
        data['TCP Sequence Number'] = packet.tcp.seq
    if hasattr(packet.tcp, 'ack'):
        data['TCP Acknowledgment Number'] = packet.tcp.ack
    if hasattr(packet.tcp, 'flags'):
        data['TCP Flags'] = packet.tcp.flags
    if hasattr(packet.tcp, 'window_size'):
        data['Window Size'] = packet.tcp.window_size
    if hasattr(packet.tcp, 'checksum'):
        data['Checksum'] = packet.tcp.checksum
    if hasattr(packet.tcp, 'urgent_pointer'):
        data['Urgent Pointer'] = packet.tcp.urgent_pointer
    if hasattr(packet.tcp, 'options'):
        data['Options'] = packet.tcp.options
    return data

def extract_udp_data(packet):
    data = {}
    if hasattr(packet.udp, 'srcport'):
        data['UDP Source Port'] = packet.udp.srcport
    if hasattr(packet.udp, 'dstport'):
        data['UDP Destination Port'] = packet.udp.dstport
    if hasattr(packet.udp, 'length'):
        data['Length'] = packet.udp.length
    if hasattr(packet.udp, 'checksum'):
        data['Checksum'] = packet.udp.checksum
    return data

def extract_fpp_data(packet):
    data = {}
    if hasattr(packet.fpp, 'session_id'):
        data['Session ID'] = packet.fpp.session_id
    if hasattr(packet.fpp, 'src_ip'):
        data['Source IP'] = packet.fpp.src_ip
    if hasattr(packet.fpp, 'dst_ip'):
        data['Destination IP'] = packet.fpp.dst_ip
    if hasattr(packet.fpp, 'src_port'):
        data['Source Port'] = packet.fpp.src_port
    if hasattr(packet.fpp, 'dst_port'):
        data['Destination Port'] = packet.fpp.dst_port
    if hasattr(packet.fpp, 'protocol'):
        data['Protocol'] = packet.fpp.protocol
    if hasattr(packet.fpp, 'length'):
        data['Length'] = packet.fpp.length
    if hasattr(packet.fpp, 'checksum'):
        data['Checksum'] = packet.fpp.checksum
    if hasattr(packet.fpp, 'timestamp'):
        data['Timestamp'] = packet.fpp.timestamp
    if hasattr(packet.fpp, 'flags'):
        data['Flags'] = packet.fpp.flags
    return data

def extract_tls_data(packet):
    data = {}
    if hasattr(packet.ssl, 'handshake_version'):
        data['SSL Version'] = packet.ssl.handshake_version
    if hasattr(packet.ssl, 'handshake_cipher_suite'):
        data['Cipher Suite'] = packet.ssl.handshake_cipher_suite
    if hasattr(packet.ssl, 'handshake_extensions_server_name'):
        data['Server Name'] = packet.ssl.handshake_extensions_server_name
    if hasattr(packet.ssl, 'handshake_certificates'):
        data['Certificates'] = packet.ssl.handshake_certificates
    return data
