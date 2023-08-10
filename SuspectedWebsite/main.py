import re

# Read PCAP file and store the contents as a string
with open('CyberSecurity2023.pcap', 'rb') as f:
    contents = f.read().decode('utf-8', errors='ignore')

# Regular expression to match domain names that end with .top
pattern = r'(https?://\S+\.top\S*)'

# Search for the pattern in the contents of the PCAP file
matches = re.findall(pattern, contents)

# Print the list of suspected website URLs
for url in matches:
    print(url)
