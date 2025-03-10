from NMdhcpserver import configure_device
from loguru import logger


commands = [
                'interface FastEthernet 1/0',
                'ipv6 address 2002:1234::1/64',
                'no shutdown'
            ]
R1_interface_IP = configure_device("2001:db8::2", "atul", "atul", commands, config = True)

ping_commands = 'ping ipv6 ff02::1 repeat 1 \n fastethernet1/0'

ping_R1 = configure_device("2001:db8::2", "atul", "atul", ping_commands, commd = True)

commands = "show ipv6 neighbors fastEthernet 1/0"

fetch_ipv6_neighbour = configure_device("2001:db8::2", "atul", "atul", commands)

for line in fetch_ipv6_neighbour.splitlines()[1:]:

    # Split the line into columns (space separated)
    ipv6 = line.split()[0]
    mac = line.split()[2]

    logger.success(f"IPv6: {ipv6} => MAC: {mac}")

R2 = "2001:db8" + ipv6[4:]

logger.success(f"R2 IPv6: {ipv6}")





