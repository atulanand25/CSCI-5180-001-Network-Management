import textwrap

from scapy.all import rdpcap, in6_addrtomac
import ipaddress


def extract_ipv6_and_mac_from_pcap(pcap_file, target_ipv6):
    """
    Extract unique IPv6 source addresses and their corresponding MAC addresses
    from a pcap file that are destined for a specific IPv6 address, excluding link-local addresses.

    :param pcap_file: Path to the pcap file
    :param target_ipv6: Target IPv6 address to filter packets
    :return: List of tuples containing (IPv6 address, MAC address)
    """
    # Extract packets
    packets = rdpcap(pcap_file)

    # Set to store unique IPv6 source addresses
    unique_ipv6_sources = set()

    for packet in packets:
        if 'IPv6' in packet and packet['IPv6'].dst == target_ipv6:
            ipv6_src = packet['IPv6'].src
            # Skip link-local addresses (fe80::/10)
            if not ipaddress.IPv6Address(ipv6_src).is_link_local:
                unique_ipv6_sources.add(ipv6_src)

    # Return a list of tuples (IPv6 address, MAC address)
    return [(ipv6, ":".join(textwrap.wrap(in6_addrtomac(ipv6).replace(':', ''), 4))) for ipv6 in unique_ipv6_sources]


def main():
    """
    Main function to extract IPv6 and corresponding MAC addresses from a pcap file.
    """
    pcap_file = "/home/netman/Downloads/lab5.pcapng"
    target_ipv6 = "2001:db8::1"
    ipv6_mac_pairs = extract_ipv6_and_mac_from_pcap(pcap_file, target_ipv6)

    print("IPv6 and Corresponding MAC Addresses (excluding link-local addresses):")
    for ipv6, mac in ipv6_mac_pairs:
        print(f"IPv6: {ipv6} => MAC: {mac}")


if __name__ == "__main__":
    main()
