from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def get_protocol(packet):
    """
    Packet ka protocol identify karta hai.
    """
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "Other"


def analyze_packet(packet):
    """
    Captured packet ki structure aur useful information display karta hai.
    """

    print("\n" + "=" * 60)
    print("New Packet Captured")
    print("=" * 60)

    # IP layer check
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = get_protocol(packet)

        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")
        print(f"Packet Length  : {len(packet)} bytes")

        # TCP information
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"TCP Flags      : {tcp_layer.flags}")

        # UDP information
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        # ICMP information
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"ICMP Type      : {icmp_layer.type}")
            print(f"ICMP Code      : {icmp_layer.code}")

        # Payload display
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print("\nPayload:")
            try:
                print(payload.decode(errors="ignore"))
            except Exception:
                print(payload)

        else:
            print("\nPayload: No payload found")

    else:
        print("Non-IP packet captured")
        print(packet.summary())


def start_sniffing():
    """
    Packet capturing start karta hai.
    """

    print("Starting packet capture...")
    print("Press Ctrl + C to stop.\n")

    sniff(
        prn=analyze_packet,
        store=False,
        count=0
    )


if __name__ == "__main__":
    start_sniffing()