from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS


# ============================================================
# PACKET STATISTICS
# ============================================================

packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0


# ============================================================
# RESET STATISTICS
# ============================================================

def reset_statistics():
    """Reset packet statistics before starting a capture."""

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count
    global other_count

    packet_count = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    other_count = 0


# ============================================================
# PAYLOAD ANALYSIS
# ============================================================

def analyze_payload(packet):
    """
    Analyze the Raw payload without dumping potentially
    sensitive or binary content to the terminal.
    """

    if Raw not in packet:
        print("Payload Type     : None")
        return

    payload = bytes(packet[Raw].load)

    # Limit the amount of data examined/displayed
    preview = payload[:100]

    # Determine whether the payload is mostly printable text
    printable_characters = sum(
        1 for byte in preview
        if 32 <= byte <= 126 or byte in (9, 10, 13)
    )

    if len(preview) == 0:
        print("Payload Type     : Empty")
        return

    printable_ratio = printable_characters / len(preview)

    if printable_ratio >= 0.85:
        try:
            text = preview.decode("utf-8", errors="replace")
            text = text.replace("\r", " ").replace("\n", " ")

            print("Payload Type     : Text")
            print(f"Payload Preview  : {text[:100]}")

        except Exception:
            print("Payload Type     : Binary/Encrypted")
            print("Payload Preview  : [not displayed]")

    else:
        print("Payload Type     : Binary/Encrypted")
        print("Payload Preview  : [not displayed]")


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count
    global other_count

    packet_count += 1

    print("\n" + "=" * 60)
    print(f"PACKET #{packet_count}")
    print("=" * 60)

    # --------------------------------------------------------
    # IP PACKET ANALYSIS
    # --------------------------------------------------------

    if IP in packet:

        print(f"Source IP        : {packet[IP].src}")
        print(f"Destination IP   : {packet[IP].dst}")

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if TCP in packet:

            tcp_count += 1

            print("Protocol         : TCP")
            print(f"Source Port      : {packet[TCP].sport}")
            print(f"Destination Port : {packet[TCP].dport}")

            if packet[TCP].sport == 80 or packet[TCP].dport == 80:
                print("Service          : HTTP")

            elif packet[TCP].sport == 443 or packet[TCP].dport == 443:
                print("Service          : HTTPS")

            else:
                print("Service          : Unknown TCP Service")

        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        elif UDP in packet:

            udp_count += 1

            print("Protocol         : UDP")
            print(f"Source Port      : {packet[UDP].sport}")
            print(f"Destination Port : {packet[UDP].dport}")

            if DNS in packet:
                print("Service          : DNS")

            elif (
                packet[UDP].sport == 1900
                or packet[UDP].dport == 1900
            ):
                print("Service          : SSDP")

            else:
                print("Service          : Unknown UDP Service")

        # ----------------------------------------------------
        # ICMP
        # ----------------------------------------------------

        elif ICMP in packet:

            icmp_count += 1

            print("Protocol         : ICMP")
            print("Service          : ICMP")

        # ----------------------------------------------------
        # OTHER IP PROTOCOLS
        # ----------------------------------------------------

        else:

            other_count += 1

            print("Protocol         : Other IP Protocol")

        # ----------------------------------------------------
        # PACKET SIZE
        # ----------------------------------------------------

        print(f"Packet Length    : {len(packet)} bytes")

        # ----------------------------------------------------
        # PAYLOAD
        # ----------------------------------------------------

        analyze_payload(packet)

    else:

        other_count += 1

        print("Non-IP packet captured.")

    print("-" * 60)


# ============================================================
# STATISTICS
# ============================================================

def display_statistics():

    print("\n" + "=" * 60)
    print("PACKET CAPTURE SUMMARY")
    print("=" * 60)

    print(f"Total Packets Captured : {packet_count}")
    print(f"TCP Packets            : {tcp_count}")
    print(f"UDP Packets            : {udp_count}")
    print(f"ICMP Packets           : {icmp_count}")
    print(f"Other Packets          : {other_count}")

    print("=" * 60)


# ============================================================
# FILTER SELECTION
# ============================================================

def choose_filter():

    print("\nChoose Capture Mode:")
    print("1. Capture All Traffic")
    print("2. Capture TCP Traffic")
    print("3. Capture UDP Traffic")
    print("4. Capture ICMP Traffic")

    choice = input("\nEnter your choice (1-4): ")

    filters = {
        "1": None,
        "2": "tcp",
        "3": "udp",
        "4": "icmp"
    }

    if choice in filters:
        return filters[choice]

    print("\nInvalid choice. Capturing all traffic.")

    return None


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print("=" * 60)
    print("        CODEALPHA NETWORK SNIFFER")
    print("=" * 60)

    reset_statistics()

    try:

        # Select protocol filter
        capture_filter = choose_filter()

        # Select packet count
        number_of_packets = int(
            input("\nHow many packets would you like to capture? ")
        )

        if number_of_packets <= 0:

            print("\nPlease enter a number greater than zero.")
            return

        print("\nStarting packet capture...")

        if capture_filter:

            print(
                f"Filter applied     : "
                f"{capture_filter.upper()}"
            )

        else:

            print("Filter applied     : ALL TRAFFIC")

        print("Press Ctrl+C to stop early.\n")

        # Start packet capture
        sniff(
            prn=packet_callback,
            count=number_of_packets,
            filter=capture_filter,
            store=False
        )

        display_statistics()

    except ValueError:

        print(
            "\nInvalid input. "
            "Please enter a valid number."
        )

    except KeyboardInterrupt:

        print("\n\nPacket capture stopped by user.")

        display_statistics()

    except PermissionError:

        print("\nPermission denied.")

        print(
            "Try running VS Code as Administrator."
        )

    except Exception as error:

        print(f"\nAn error occurred: {error}")


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()