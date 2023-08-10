# List of popular search engines to check for
import re

SEARCH_ENGINES = ['bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com', 'wolframalpha.com']


def identify_suspicious_traffic(content):
    suspicious_packets = []
    # Iterate over each packet in the PCAP file
    while content:
        # Extract Ethernet header
        ethernet_header = content[:14]
        packet_number = int.from_bytes(ethernet_header[8:10], byteorder='big')
        content = content[14:]

        # Extract IP header
        ip_header = content[:20]
        content = content[20:]

        # Extract TCP header
        tcp_header = content[:20]
        content = content[20:]

        # Extract HTTP payload
        http_payload = b''
        if tcp_header and tcp_header[1] == 80:
            data_offset = (tcp_header[12] >> 4) * 4
            http_payload = content[data_offset:]
            content = content[data_offset:]

        # Check for suspicious traffic
        if len(http_payload) > 10000:
            suspicious_packets.append(packet_number)

    return suspicious_packets


def get_http_response_headers_dict(payload):
    headers_dict = {}

    # Split the payload into header and body
    header_end = payload.find(b'\r\n\r\n')
    if header_end == -1:
        return headers_dict

    header_bytes = payload[:header_end]
    header_lines = header_bytes.split(b'\r\n')

    # Parse the headers into a dictionary
    for line in header_lines[1:]:
        parts = line.split(b':', maxsplit=1)
        if len(parts) == 2:
            key = parts[0].strip().lower()
            value = parts[1].strip()
            headers_dict[key] = value

    return headers_dict


def get_search_keywords(payload):
    # Check if the payload is a search engine request
    for engine in SEARCH_ENGINES:
        if engine.encode() in payload:
            # Extract the query string from the URL
            url_start = payload.find(b'GET ')
            url_end = payload.find(b' HTTP/')
            if url_start == -1 or url_end == -1:
                return ''
            url = payload[url_start + 4:url_end]
            query_start = url.find(b'?q=')
            if query_start == -1:
                return ''
            query_end = url.find(b'&', query_start + 3)
            if query_end == -1:
                query_end = len(url)
            query = url[query_start + 3:query_end]
            return query.decode()
    return ''


def identify_suspicious_ip_addresses(content):
    suspicious_ips = []
    # Iterate over each packet in the PCAP file
    while content:
        # Extract Ethernet header
        ethernet_header = content[:14]
        content = content[14:]

        # Extract IP header
        ip_header = content[:20]
        content = content[20:]

        # Extract source and destination IP addresses
        source_ip = '.'.join(map(str, ip_header[12:16]))
        dest_ip = '.'.join(map(str, ip_header[16:20]))

        # Check for suspicious IP addresses
        ip_regex = re.compile(r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.).*$')
        if ip_regex.match(source_ip) or ip_regex.match(dest_ip):
            suspicious_ips.append((source_ip, dest_ip))

    return suspicious_ips


def check_protocol_anomalies(content):
    anomalies = []

    while content:
        # Extract Ethernet header
        ethernet_header = content[:14]
        content = content[14:]

        # Extract IP header
        ip_header = content[:20]
        content = content[20:]

        # Extract TCP header
        tcp_header = content[:20]
        content = content[20:]

        # Extract UDP header
        udp_header = content[:8]
        content = content[8:]

        # Check for protocol anomalies
        if tcp_header and udp_header:
            anomalies.append(('TCP and UDP headers present', f'Packet length: {len(ethernet_header + ip_header + tcp_header + udp_header)}'))
        elif tcp_header and tcp_header[2] == 0:
            anomalies.append(
                ('TCP header length is 0', f'Packet length: {len(ethernet_header + ip_header + tcp_header)}'))
        elif udp_header and len(udp_header) < 8:
            anomalies.append(('UDP header length is less than 8 bytes',
                              f'Packet length: {len(ethernet_header + ip_header + udp_header)}'))

    return anomalies


def check_dns_tunnelling(content):
    suspicious_packets = []

    # Iterate over each packet in the PCAP file
    while content:
        # Extract Ethernet header
        ethernet_header = content[:14]
        packet_number = int.from_bytes(ethernet_header[8:10], byteorder='big')
        content = content[14:]

        # Extract IP header
        ip_header = content[:20]
        content = content[20:]

        # Extract UDP header
        udp_header = content[:8]
        content = content[8:]

        # Extract DNS payload
        dns_payload = b''
        if udp_header and int.from_bytes(udp_header[4:], byteorder='big') > 12:
            dns_payload = content[12:]
            content = content[12:]

        # Check for DNS tunnelling
        if len(dns_payload) > 255:
            suspicious_packets.append(packet_number)

    return suspicious_packets


# Open the PCAP file and read the content
filename = input("Enter the name of the PCAP file: ")
with open(filename, 'rb') as f:
    content = f.read()

# Take user input for selecting the function to run
while True:
    print("Identifying Potential Security threats In a PCAP file ")
    print("\nSelect an option:")
    print("1. Identify suspicious traffic")
    print("2. Search for the Suspicious Search Keywords ")
    print("3. Check for suspicious IP addresses")
    print("4. Check for Protocol Anomalies ")
    print("5. Check for DNS Tunnelling ")
    print("6. Exiting the Program ")
    choice = input("Enter your choice (1/2/3/4/5/6): ")

    if choice == '1':
        suspicious_packets = identify_suspicious_traffic(content)
        print(f"\nFound {len(suspicious_packets)} suspicious packets: {suspicious_packets}")
    elif choice == '2':
        # Iterate over each packet in the PCAP file
        while content:
            # Extract Ethernet header
            ethernet_header = content[:14]
            packet_number = int.from_bytes(ethernet_header[8:10], byteorder='big')
            content = content[14:]

            # Extract IP header
            ip_header = content[:20]
            content = content[20:]

            # Extract TCP header
            tcp_header = content[:20]
            content = content[20:]

            # Extract HTTP payload
            http_payload = b''
            if tcp_header and tcp_header[1] == 80:
                data_offset = (tcp_header[12] >> 4) * 4
                http_payload = content[data_offset:]
                content = content[data_offset:]

            # Get search keywords from HTTP payload
            keywords = get_search_keywords(http_payload)
            if keywords:
                print(f"\nFound search keywords in packet {packet_number}: {keywords}")
    elif choice == '3':
        suspicious_ips = identify_suspicious_ip_addresses(content)
        print(f"\nFound {len(suspicious_ips)} suspicious IP addresses: {suspicious_ips}")
    elif choice == '4':
        protocol_anomalies = check_protocol_anomalies(content)
        print(f"\nFound {len(protocol_anomalies)} protocol anomalies: ")
        for anomaly in protocol_anomalies:
            print(f"\t{anomaly[0]} - {anomaly[1]}")
    elif choice == '5':
        suspicious_packets = check_dns_tunnelling(content)
        print(f"\nFound {len(suspicious_packets)} suspicious packets: {suspicious_packets}")
    elif choice == '6':
        print("Exiting program...")
        break
    else:
        print("Invalid choice, please try again.")
