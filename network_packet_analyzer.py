from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print("Source IP:", ip_src, "Destination IP:", ip_dst," Protocol:", protocol)

        if packet.haslayer(TCP):
            print("Protocol: TCP")
            if packet.haslayer(Raw):
                print(f"Payload:",packet[Raw].load)
        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            if packet.haslayer(Raw):
                print(f"Payload:",packet[Raw].load)
        
        print("-" * 50)

def main():
    print("Starting packet sniffing...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
