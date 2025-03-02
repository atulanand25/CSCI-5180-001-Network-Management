from NMtcpdump import extract_ipv6_and_mac_from_pcap
from NMdhcpserver import configure_device
from NMsnmp import collect_router_data
import ipaddress

ipv6_mac_pairs = extract_ipv6_and_mac_from_pcap("/home/netman/Downloads/lab5.pcapng", "2001:db8::1")

commands = "show ipv6 neighbors fastEthernet 0/0"

fetch_ipv6_neighbour = configure_device("198.51.100.1", "atul", "atul", commands)

for line in fetch_ipv6_neighbour.splitlines()[1:]:

    # Split the line into columns (space separated)
    ipv6 = line.split()[0]
    mac = line.split()[2]
    commands = "show running-config | include hostname"
    if not ipaddress.IPv6Address(ipv6).is_link_local:
        fetch_hostname = configure_device(ipv6, "atul", "atul", commands)
        if fetch_hostname == "hostname R5":

            commands = [
                'interface FastEthernet 0/0',
                'ip address 198.51.101.5 255.255.255.0'
            ]

            R5_interface_IP = configure_device(ipv6, "atul", "atul", commands, config = True)

            commands = [
                'ip dhcp pool R3',
                'host 198.51.101.3 255.255.255.0',
                f'client-identifier {ipv6_mac_pairs[0][1]}'
            ]

            R5_DHCP_STATIC_R3  = configure_device(ipv6, "atul", "atul", commands, config = True)

            commands = [
                'ip dhcp pool R2',
                'host 198.51.101.2 255.255.255.0',
                f'client-identifier {ipv6_mac_pairs[1][1]}'
            ]

            R5_DHCP_STATIC_R2 = configure_device(ipv6, "atul", "atul", commands, config = True)

            commands = [
                'ip dhcp pool MYPOOL',
                'network 198.51.101.0 255.255.255.0'
            ]

            R5_DHCP_POOL = configure_device(ipv6, "atul", "atul", commands, config = True)

            commands = 'show ip dhcp binding'

            fetch_dhcp_binding = configure_device(ipv6, "atul", "atul", commands)

routers = ['198.51.102.1', '198.51.101.7', '198.51.101.1', '198.51.100.1', '198.51.101.5']

collect_router_data("atul", routers)