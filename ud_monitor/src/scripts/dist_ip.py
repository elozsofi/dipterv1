from scapy.all import rdpcap, IP, UDP, TCP, IPv6
from scapy.layers.inet import Ether
from scapy.contrib.gtp import GTP_U_Header

# Step 1: Read the pcap file
packets = rdpcap("output.pcap")

# Set to store distinct inner destination IPs
output_data = []

# Step 2: Iterate over each packet
for pkt in packets:
    if UDP in pkt and pkt[UDP].sport == 2152 and pkt[IP].src == "10.242.136.51":
        # Step 3: Check if the packet has GTP-U header and extract inner IP
        if GTP_U_Header in pkt:
            inner_ip = pkt[GTP_U_Header].payload
            if IP in inner_ip:
                user_ip = inner_ip[IP].dst
                service_ip = inner_ip[IP].src
                protocol = 'UDP' if UDP in inner_ip else 'TCP'
                service_port = inner_ip[UDP].dport if protocol == 'UDP' else inner_ip[TCP].dport
                output_data.append(f"{user_ip};{service_ip};{service_port};{protocol}")
            elif IPv6 in inner_ip:
                user_ip = inner_ip[IPv6].dst
                service_ip = inner_ip[IPv6].src
                protocol = 'UDP' if UDP in inner_ip else 'TCP'
                service_port = inner_ip[UDP].dport if protocol == 'UDP' else inner_ip[TCP].dport
                output_data.append(f"{user_ip};{service_ip};{service_port};{protocol}")
            
    elif UDP in pkt and pkt[UDP].sport == 2152 and pkt[IP].dst == "10.242.136.51":
        # Step 3: Check if the packet has GTP-U header and extract inner IP
        if GTP_U_Header in pkt:
            inner_ip = pkt[GTP_U_Header].payload
            if IP in inner_ip:
                user_ip = inner_ip[IP].src
                service_ip = inner_ip[IP].dst
                protocol = 'UDP' if UDP in inner_ip else 'TCP'
                service_port = inner_ip[UDP].sport if protocol == 'UDP' else inner_ip[TCP].sport
                output_data.append(f"{user_ip};{service_ip};{service_port};{protocol}")
            elif IPv6 in inner_ip:
                user_ip = inner_ip[IPv6].src
                service_ip = inner_ip[IPv6].dst
                protocol = 'UDP' if UDP in inner_ip else 'TCP'
                service_port = inner_ip[UDP].sport if protocol == 'UDP' else inner_ip[TCP].sport
                output_data.append(f"{user_ip};{service_ip};{service_port};{protocol}")


# Step 4: Write the distinct IPs to a text file
with open("output_data.txt", "w") as file:
    for entry in output_data:
        file.write(entry + "\n")

print(f"Extracted {len(output_data)} entries.")
