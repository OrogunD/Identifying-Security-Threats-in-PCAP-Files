# List of popular search engines to check for
search_engines = ['bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com', 'wolframalpha.com']

# Open the PCAP file and read the content
with open('CyberSecurity2023.pcap', 'rb') as f:
    content = f.read()

packet_counter = 0


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
    for engine in search_engines:
        if engine.encode() in payload:
            # Extract the query string from the URL
            url_start = payload.find(b'GET ')
            url_end = payload.find(b' HTTP/')
            if url_start == -1 or url_end == -1:
                return ''
            url = payload[url_start+4:url_end]
            query_start = url.find(b'?q=')
            if query_start == -1:
                return ''
            query_end = url.find(b'&', query_start+3)
            if query_end == -1:
                query_end = len(url)
            query = url[query_start+3:query_end]
            return query.decode()
    return ''


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

    # Check if the payload contains a search engine URL
    for search_engine in search_engines:
        if search_engine.encode() in http_payload:
            # Extract the search engine name
            search_engine_name = search_engine.split('.')[0].capitalize()
            print(f"\nPacket {packet_number}, The user searched on {search_engine_name}:")
            # Extract the recommended website and the actual website accessed
            http_response_headers_dict = get_http_response_headers_dict(http_payload)
            recommended_website = ''
            actual_website = ''
            if b'refresh' in http_response_headers_dict:
                refresh_header_value = http_response_headers_dict[b'refresh']
                if b';url=' in refresh_header_value:
                    recommended_website = refresh_header_value.split(b';url=')[1].decode()
            if b'referer' in http_response_headers_dict:
                actual_website = http_response_headers_dict[b'referer'].decode()
            print(f"Recommended website: {recommended_website}")
            print(f"Actual website accessed: {actual_website}")
            # Extract the search keywords
            search_keywords = get_search_keywords(http_payload)
            if search_keywords:
                print(f"Search keywords: {search_keywords}")
            else:
                print("No search keywords found")

    packet_counter += 1
