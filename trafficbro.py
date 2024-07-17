import os
from scapy.all import *


def analyze_pcap(file_path):
    print(f"Analyzing {file_path}...")
    packets = rdpcap(file_path)

    connection_info = {}
    results = []

    for packet in packets:
        packet_info = {
            "Capture Time": packet.time,
            "Source IP": packet[IP].src if IP in packet else None,
            "Destination IP": packet[IP].dst if IP in packet else None,
            "Source Port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None),
            "Destination Port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None),
            "Protocol Type": packet.proto if IP in packet else None,
            "Packet Length": len(packet),
            "TCP Flags": packet[TCP].flags if TCP in packet else None,
            "Payload Size": len(packet.payload) if IP in packet else None,
            "Sequence Number": packet[TCP].seq if TCP in packet else None,
            "Acknowledgment Number": packet[TCP].ack if TCP in packet else None,
        }

        # Extract DNS Information
        if DNS in packet:
            packet_info["DNS Query Type"] = packet[DNS].qr
            packet_info["DNS Query Name"] = packet[DNS].qd.qname.decode() if packet[DNS].qd else None

        # Extract ICMP Information
        if ICMP in packet:
            packet_info["ICMP Type"] = packet[ICMP].type
            packet_info["ICMP Code"] = packet[ICMP].code


        # Store results
        results.append(packet_info)

        # Track connection information for duration analysis
        src_dst = (packet_info["Source IP"], packet_info["Destination IP"])
        if src_dst not in connection_info:
            connection_info[src_dst] = {
                "Start Time": packet_info["Capture Time"],
                "End Time": packet_info["Capture Time"]
            }
        else:
            connection_info[src_dst]["End Time"] = packet_info["Capture Time"]

    # Calculate connection durations
    for connection, times in connection_info.items():
        duration = times["End Time"] - times["Start Time"]
        print(f"Connection {connection}: Duration = {duration:.4f} seconds")

    return results

    
def main(pcap_dir):
    for filename in os.listdir(pcap_dir):
        if filename.endswith('.pcap'):
            file_path = os.path.join(pcap_dir, filename)
            results = analyze_pcap(file_path)

            print(f"\nResults for {filename}:")
            for res in results:
                print(res)
            print("-" * 40)

if __name__ == '__main__':
    pcap_directory = input("Enter the path to the directory containing PCAP files: ")
    main(pcap_directory)
