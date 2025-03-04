from NMtcpdump import extract_ipv6_and_mac_from_pcap
from NMdhcpserver import configure_device
from NMsnmp import collect_router_data, cpu_utilization, plot_and_save_cpu_utilization
import ipaddress
from loguru import logger

ipv6_mac_pairs = extract_ipv6_and_mac_from_pcap("/home/netman/Downloads/lab5.pcapng", "2001:db8::1")

logger.debug("IPv6 and Corresponding MAC Addresses (excluding link-local addresses):")

for ipv6, mac in ipv6_mac_pairs:
    logger.success(f"IPv6: {ipv6} => MAC: {mac}")

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
                'ip dhcp pool R2',
                'host 198.51.101.3 255.255.255.0',
                f'client-identifier {ipv6_mac_pairs[0][1]}'
            ]

            R5_DHCP_STATIC_R2  = configure_device(ipv6, "atul", "atul", commands, config = True)

            commands = [
                'ip dhcp pool R3',
                'host 198.51.101.2 255.255.255.0',
                f'client-identifier {ipv6_mac_pairs[1][1]}'
            ]

            R5_DHCP_STATIC_R3 = configure_device(ipv6, "atul", "atul", commands, config = True)

            commands = [
                'ip dhcp pool MYPOOL',
                'network 198.51.101.3 255.255.255.0'
            ]

            R5_DHCP_POOL = configure_device(ipv6, "atul", "atul", commands, config = True)

            commands = 'show ip dhcp binding'

            fetch_dhcp_binding = configure_device(ipv6, "atul", "atul", commands)

routers = ['198.51.102.1', '198.51.101.1', '198.51.101.6', '198.51.100.1', '198.51.101.5']

devices_info = collect_router_data("atul", routers)

# Iterating over the devices_info dictionary and printing key-value pairs
formatted_info = "\n".join(f"{router}: {info}" for router, info in devices_info.items())

# Log the information with each entry on a new line
logger.success(f"Router Information:\n{formatted_info}")

device_ip = '198.51.102.1'  # Replace with the device's IP address
community = 'atul'  # Replace with the SNMP community string

# Fetch CPU utilization data
times, cpu_values = cpu_utilization(device_ip, community)

# Plot and save the CPU utilization graph as a JPG file
plot_and_save_cpu_utilization(times, cpu_values)
