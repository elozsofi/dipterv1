import sys
import pcapy
import struct

ETHERNET_HEADER_LEN = 14

def is_tcp_packet(packet):
    if len(packet) < ETHERNET_HEADER_LEN + 1:
        return False

    eth_type = struct.unpack('!H', packet[12:14])[0]

    if eth_type == 0x0800:
        if len(packet) < ETHERNET_HEADER_LEN + 20:
            return False
        ip_header_offset = ETHERNET_HEADER_LEN
        protocol = packet[ip_header_offset + 9]
        return protocol == 6

    elif eth_type == 0x86DD:
        if len(packet) < ETHERNET_HEADER_LEN + 40:
            return False
        ip_header_offset = ETHERNET_HEADER_LEN
        next_header = packet[ip_header_offset + 6]
        return next_header == 6

    return False

def calculate_jitter(pcap_file):
    try:
        reader = pcapy.open_offline(pcap_file)
        reader.setfilter('')

        timestamps = []

        while True:
            try:
                header, packet = reader.next()
                if header is None:
                    break

                if not is_tcp_packet(packet):
                    continue

                ts_sec, ts_usec = header.getts()
                timestamp = ts_sec + ts_usec / 1_000_000.0
                timestamps.append(timestamp)

            except pcapy.PcapError:
                break

        if len(timestamps) < 3:
            print("Not enough packets to calculate jitter.")
            return

        jitter = 0.0
        t_prev = timestamps[1]
        t_prev2 = timestamps[0]

        for t_i in timestamps[2:]:
            inter_arrival_current = t_i - t_prev
            inter_arrival_prev = t_prev - t_prev2
            D_i = inter_arrival_current - inter_arrival_prev
            abs_D_i = abs(D_i)
            jitter += (abs_D_i - jitter) / 16.0
            t_prev2 = t_prev
            t_prev = t_i

        print(f"Number of packets processed: {len(timestamps)}")
        print(f"EWMA jitter: {jitter * 1000:.3f} ms")

    except Exception as e:
        print(f"Error processing pcap file: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python jitter_calc.py <file.pcap>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    calculate_jitter(pcap_file)

if __name__ == "__main__":
    main()