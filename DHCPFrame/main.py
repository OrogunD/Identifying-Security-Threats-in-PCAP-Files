import socket
import datetime

with open('CyberSecurity2023.pcap', 'rb') as pcap_file:
    pcap_global_header = pcap_file.read(24)

    # Read the first packet header
    pcap_packet_header = pcap_file.read(16)

    # Extract the timestamp, in seconds and microseconds
    timestamp_seconds = int.from_bytes(pcap_packet_header[0:4], byteorder='little', signed=False)
    timestamp_microseconds = int.from_bytes(pcap_packet_header[4:8], byteorder='little', signed=False)

    # Convert the timestamp to a datetime object in GMT
    timestamp = datetime.datetime.utcfromtimestamp(timestamp_seconds + (timestamp_microseconds / 1000000))

    # Extract the length of the packet
    packet_length = int.from_bytes(pcap_packet_header[8:12], byteorder='little', signed=False)

    # Read the packet data
    packet_data = pcap_file.read(packet_length)

    # Extracting the source and destination MAC addresses
    source_mac_address = ':'.join([f'{x:02x}' for x in packet_data[6:12]])
    destination_mac_address = ':'.join([f'{x:02x}' for x in packet_data[0:6]])

    # Extracting the source and destination IP addresses
    source_ip_address = socket.inet_ntoa(packet_data[26:30])
    destination_ip_address = socket.inet_ntoa(packet_data[30:34])

    # Extracting the hostname from the packet data
    option_code_index = packet_data.find(bytes([0x0C]))

    if option_code_index != -1:
        # Calculate the index of the option length byte
        option_length_index = option_code_index + 1
        # Read the option length byte
        option_length = packet_data[option_length_index]
        # Calculate the index of the first hostname byte
        hostname_index = option_length_index + 1
        # Calculate the index of the last hostname byte
        hostname_end_index = hostname_index + option_length
        # Extract the hostname bytes using slice method
        hostname_ascii = packet_data[hostname_index:hostname_end_index].decode('utf-8', errors='ignore')
    else:
        hostname_ascii = None

    # Print the extracted information from the DHCP Frame
    print(f'Timestamp: {timestamp}')
    print(f'Packet length of DHCP Frame: {packet_length}')
    print(f'Source MAC address: {source_mac_address}')
    print(f'Destination MAC address: {destination_mac_address}')
    print(f'Source IP address: {source_ip_address}')
    print(f'Destination IP address: {destination_ip_address}')
    print(f'Hostname of the PC: {hostname_ascii}')