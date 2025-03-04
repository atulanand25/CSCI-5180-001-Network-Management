import json
from threading import Thread
from easysnmp import Session
import time
import plotly.graph_objects as go
import ipaddress
from loguru import logger

# Dictionary to store router information
devices_info = {}

def perform_snmp_walk(oid: str, community: str, target: str):
    """Performs an SNMP walk operation to retrieve multiple OID values from the target device."""
    session = Session(hostname=target, community=community, version=2)
    walk_data = session.walk(oid)
    return walk_data


def fetch_snmp_interface_data(community: str, target: str):
    """Retrieves SNMP-based network interface information for a given target device."""
    # Retrieve hostname for the router (system name)
    hostname = perform_snmp_walk('1.3.6.1.2.1.1.5', community, target)

    if not hostname:
        logger.error(f"SNMP Walk failed to retrieve hostname for target: {target}")
        return

    hostname = hostname[0].value
    devices_info[hostname] = {}

    # Fetch data in parallel: IPv4, interfaces, subnet masks, IPv6, and link-local IPv6
    ipv4_addresses = perform_snmp_walk('1.3.6.1.2.1.4.20.1.2', community, target)
    interfaces = perform_snmp_walk('1.3.6.1.2.1.31.1.1.1.1', community, target)
    subnet_masks = perform_snmp_walk('1.3.6.1.2.1.4.20.1.3', community, target)
    ipv6_addresses = perform_snmp_walk('1.3.6.1.2.1.4.34.1.3.2.16', community, target)
    link_local_ipv6 = perform_snmp_walk('1.3.6.1.2.1.4.34.1.3.4.20', community, target)
    interface_status = perform_snmp_walk('1.3.6.1.2.1.2.2.1.8', community, target)

    # If any data is missing, log the error
    missing_data = []
    if not ipv4_addresses: missing_data.append("IPv4 addresses")
    if not interfaces: missing_data.append("interfaces")
    if not subnet_masks: missing_data.append("subnet masks")
    if not ipv6_addresses: missing_data.append("IPv6 addresses")
    if not link_local_ipv6: missing_data.append("link-local IPv6 addresses")
    if not interface_status: missing_data.append("interface status")

    if missing_data:
        logger.error(f"SNMP Walk failed to retrieve: {', '.join(missing_data)} for target: {target}")
        return

    # Combine IPv4 and IPv6 processing in one loop
    for var_bind in ipv4_addresses + ipv6_addresses + link_local_ipv6:
        ip_address = oid_to_ipv6(var_bind.oid) if '34' in str(var_bind.oid) else '.'.join(str(var_bind.oid).split('.')[-4:])
        index = var_bind.value

        # Initialize the device entry if not present
        if index not in devices_info[hostname]:
            devices_info[hostname][index] = {'addresses': {}, 'status': {}, 'interface_name': None}

        if '34' in str(var_bind.oid):  # For IPv6
            # Ensure v6 dictionary exists directly
            if 'v6' not in devices_info[hostname][index]['addresses']:
                devices_info[hostname][index]['addresses']['v6'] = {}

            if '34.1.3.4.20' in str(var_bind.oid):
                devices_info[hostname][index]['addresses']['v6']['link-local'] = str(ipaddress.IPv6Address(ip_address).compressed)
            else:
                devices_info[hostname][index]['addresses']['v6']['global'] = str(ipaddress.IPv6Address(ip_address).compressed)
        else:  # For IPv4
            devices_info[hostname][index]['addresses']['v4'] = ip_address

    # Process interfaces and statuses
    for var_bind in interfaces + interface_status:
        index = str(var_bind.oid).split('.')[-1]
        if index in devices_info[hostname]:
            if 'iso.3.6.1.2.1.31' in var_bind.oid:
                devices_info[hostname][index]['interface_name'] = str(var_bind.value)
            else:
                status = 'Up' if str(var_bind.value) == '1' else 'Down'
                devices_info[hostname][index]['status'] = status

    # Process subnet masks
    for var_bind in subnet_masks:
        ip_address, subnet_mask = '.'.join(str(var_bind.oid).split('.')[-4:]), str(var_bind.value)
        for index, value in devices_info[hostname].items():
            if ip_address in value['addresses'].get('v4', ''):
                network = ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask}", strict=False)
                devices_info[hostname][index]['addresses']['v4'] = ip_address + "/" + str(network.prefixlen)

    return devices_info

def collect_router_data(community: str, targets: list):
    """Collects router interface information via SNMP and retrieves IPv6 addresses via SNMP for a list of target devices."""
    threads = [Thread(target=fetch_snmp_interface_data, args=(community, target)) for target in targets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for target in targets:
        if not devices_info:
            print(f"No devices found or SNMP data could not be retrieved for target: {target}. Skipping...")
            continue

    with open('router_info.txt', 'w') as file:
        json.dump(devices_info, file, indent=4)

    return devices_info



def cpu_utilization(device_ip, community, interval=5, duration=120):
    """Calculates the average CPU utilization for a given device over a 2-minute period, with 5-second intervals."""

    cpu_oid = '1.3.6.1.4.1.9.9.109.1.1.1.1.6'

    # Lists to store time and CPU utilization values
    times = [x for x in range(0, duration, interval)]
    cpu_values = []

    for i in range(duration//interval):
        cpu_data = perform_snmp_walk(oid = cpu_oid, community=community, target=device_ip)

        for var_bind in cpu_data:
            cpu_values.append(var_bind.value)
            time.sleep(interval)

    # Return the time and CPU utilization data
    return times, cpu_values


def oid_to_ipv6(oid: str) -> str:
    """Converts an SNMP OID to an IPv6 address format."""
    # Extract the relevant part of the OID and split it into chunks

    if "34.1.3.4.20" in oid:
        oid_parts = oid[28:-9].split(".")
    else:
        oid_parts = oid[28:].split(".")

    # Convert the OID to the IPv6 format
    ipv6_address = ":".join(
        [f"{int(oid_parts[i]):02x}{int(oid_parts[i + 1]):02x}"
         for i in range(0, len(oid_parts), 2)]
    )

    return ipv6_address


def plot_and_save_cpu_utilization(times, cpu_values, filename="cpu_utilization.jpg"):
    """Plots the CPU utilization over time using Plotly and saves the figure as a JPG file."""
    fig = go.Figure()

    # Plotting the CPU utilization vs Time
    fig.add_trace(go.Scatter(x=times, y=cpu_values, mode='lines+markers', name='CPU Utilization'))

    # Add title and labels
    fig.update_layout(
        title="CPU Utilization Over Time",
        xaxis_title="Time (seconds)",
        yaxis_title="CPU Utilization (%)",
    )

    # Save the figure as a JPG file
    fig.write_image(filename)

    # Show the plot
    fig.show()


def main():
    """
    Main function to extract snmp data from devices.
    """
    routers = ['198.51.102.1']
    device = collect_router_data("atul", routers)
    logger.info(device)

    # device_ip = '198.51.102.1'  # Replace with the device's IP address
    # community = 'atul'  # Replace with the SNMP community string
    #
    # # Fetch CPU utilization data
    # times, cpu_values = cpu_utilization(device_ip, community)
    #
    # # Plot and save the CPU utilization graph as a JPG file
    # plot_and_save_cpu_utilization(times, cpu_values)


if __name__ == "__main__":
    main()
