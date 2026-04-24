import re

# Function to convert an IP address to hexadecimal with "0x" prefix
def ip_to_hex(ip):
    return '0x' + ''.join(f'{int(octet):02X}' for octet in ip.split('.'))

# Read the input file and process it
input_file = 'nodes.txt'
output_file = 'nodes_hex.txt'

# Regular expression to match an IPv4 address
ip_regex = re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b')

# Open input and output files
with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
    for line in infile:
        # Replace all IP addresses in the line with their hexadecimal representation
        new_line = ip_regex.sub(lambda match: ip_to_hex(match.group()), line)
        outfile.write(new_line)

print(f"Conversion complete. Output saved to {output_file}")