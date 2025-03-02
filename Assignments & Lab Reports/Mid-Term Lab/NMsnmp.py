from json import dump
from threading import Thread
from easysnmp import Session
import time
import plotly.graph_objects as go

# Dictionary to store router information
devices_info = {}

def perform_snmp_walk(oid: str, community: str, target: str):
    """Performs an SNMP walk operation to retrieve multiple OID values from the target device."""
    session = Session(hostname=target, community=community, version=2)
    walk_data = session.walk(oid)
    return walk_data

def fetch_snmp_interface_data(community: str, target: str):
    """Retrieves SNMP-based network interface information for a given target device."""
    hostname = perform_snmp_walk('1.3.6.1.2.1.1.5', community, target)
    if not hostname:
        print(f"SNMP Walk failed to retrieve hostname for target: {target}")
        return
    hostname = hostname[0].value
    devices_info[hostname] = {'addresses': {}, 'status': {}}

    device_data = {}
    for var_bind in perform_snmp_walk('1.3.6.1.2.1.4.20.1.2', community, target):
        index, ip_address = str(var_bind.value), '.'.join(str(var_bind.oid).split('.')[-4:])
        device_data[index] = [ip_address]

    for var_bind in perform_snmp_walk('1.3.6.1.2.1.31.1.1.1.1', community, target):
        index, interface_name = str(var_bind.oid).split('.')[-1], str(var_bind.value)
        if index in device_data:
            device_data[index].append(interface_name)

    for var_bind in perform_snmp_walk('1.3.6.1.2.1.4.20.1.3', community, target):
        ip_address, subnet_mask = '.'.join(str(var_bind.oid).split('.')[-4:]), str(var_bind.value)
        for key, value in device_data.items():
            if ip_address in value[0]:
                device_data[key].append(subnet_mask)

    for var_bind in perform_snmp_walk('1.3.6.1.2.1.2.2.1.8', community, target):
        index, status = str(var_bind.oid).strip('.')[-1], 'Up' if str(var_bind.value) == '1' else 'Down'
        if index in device_data:
            device_data[index].append(status)

    for value in device_data.values():
        devices_info[hostname]['addresses'][value[1]] = {'v4': {value[0]: value[2]}, 'v6': {}}
        devices_info[hostname]['status'][value[1]] = value[3]
    return device_data

def retrieve_ipv6_addresses(hostname: str, target: str):
    """Retrieves IPv6 addresses from the device using SNMP."""
    session = Session(hostname=target, community='atul', version=2)

    # Example interfaces
    for interface in ['FastEthernet0/0', 'FastEthernet1/0']:
        output = session.get(f'1.3.6.1.2.1.4.20.1.2.{interface}')
        if output:
            ipv6_info = output.split('\n')[1].strip().split()
            devices_info[hostname]['addresses'].setdefault(interface, {'v4': {}, 'v6': {}})['v6'] = {
                ipv6_info[0].strip(','): ipv6_info[3]}

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

        hostname = list(devices_info.keys())[-1]
        # retrieve_ipv6_addresses(hostname, target)

    # with open('router_info.json', 'w') as file:
    #     dump(devices_info, file, indent=4)



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
    routers = ['198.51.102.1', '198.51.101.7', '198.51.101.1', '198.51.100.1', '198.51.101.5']
    collect_router_data("atul", routers)

    device_ip = '198.51.102.1'  # Replace with the device's IP address
    community = 'atul'  # Replace with the SNMP community string

    # Fetch CPU utilization data
    times, cpu_values = cpu_utilization(device_ip, community)

    # Plot and save the CPU utilization graph as a JPG file
    plot_and_save_cpu_utilization(times, cpu_values)


if __name__ == "__main__":
    main()
