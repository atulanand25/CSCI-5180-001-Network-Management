#!/usr/bin/env python3

try:
    import os
    import subprocess
    from prettytable import PrettyTable
    from loguru import logger
    import argparse
except ModuleNotFoundError as e:
    missing_module = str(e).split("'")[1]
    print(f"Error: The module '{missing_module}' is not installed.")
    print(f"Please install it using 'pip install {missing_module}' and try again.")
    exit(1)


def argparse_helper():
    """
    Parses command-line arguments for the script.
    """
    parser = argparse.ArgumentParser(
        description="This script fetches SNMP details from a router using OIDs from a file and displays them in a table."
    )

    # Common arguments
    parser.add_argument(
        "-i",
        "--ip",
        required=True,
        type=str,
        help="IP address of the SNMP-enabled device.",
    )
    parser.add_argument(
        "-v",
        "--version",
        required=True,
        type=str,
        choices=["1", "2c", "3"],
        help="SNMP version (1, 2c, or 3).",
    )
    parser.add_argument(
        "-c", "--community", type=str, help="SNMP community string (for v1 and v2c)."
    )
    parser.add_argument(
        "-f",
        "--oid_file",
        required=True,
        type=str,
        help="Path to the file containing OIDs (one per line).",
    )

    # SNMPv3-specific arguments
    parser.add_argument("--username", type=str, help="SNMPv3 username.")
    parser.add_argument(
        "--sec_level",
        type=str,
        choices=["noAuthNoPriv", "authNoPriv", "authPriv"],
        help="SNMPv3 security level.",
    )
    parser.add_argument(
        "--auth_protocol",
        type=str,
        choices=["MD5", "SHA"],
        help="SNMPv3 authentication protocol.",
    )
    parser.add_argument(
        "--auth_password", type=str, help="SNMPv3 authentication password."
    )
    parser.add_argument(
        "--priv_protocol",
        type=str,
        choices=["DES", "AES"],
        help="SNMPv3 privacy protocol.",
    )
    parser.add_argument("--priv_password", type=str, help="SNMPv3 privacy password.")

    return parser.parse_args()


def fetch_snmp_data(ip, version, oids, community=None, snmpv3_params=None):
    """
    Fetches SNMP data for a list of OIDs using the `snmpget` command.
    Args:
        ip (str): IP address of the SNMP-enabled device.
        version (str): SNMP version (1, 2c, or 3).
        oids (list): List of OIDs to fetch from the device.
        community (str): SNMP community string (for v1 and v2c).
        snmpv3_params (dict): SNMPv3-specific parameters.

    Returns:
        list: A list of tuples with OID and its corresponding output.
    """
    results = {}
    for desc, oid in oids.items():
        try:
            if version in ["1", "2c"]:
                command = f"snmpget -v {version} -c {community} {ip} {oid}"
            elif version == "3":
                command = f"snmpget -v3 -u {snmpv3_params['username']} -l {snmpv3_params['sec_level']} "
                if snmpv3_params["sec_level"] in ["authNoPriv", "authPriv"]:
                    command += f"-a {snmpv3_params['auth_protocol']} -A {snmpv3_params['auth_password']} "
                if snmpv3_params["sec_level"] == "authPriv":
                    command += f"-x {snmpv3_params['priv_protocol']} -X {snmpv3_params['priv_password']} "
                command += f"{ip} {oid}"

            logger.info(f"Executing command: {command}")
            result = subprocess.check_output(command, shell=True, text=True)
            logger.success(f"Fetched data for OID {oid}: {result.strip()}")

            # Only update the results if the fetch is successful
            if result:
                results[desc] = result.strip()

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to fetch data for OID {oid}: {e}")

    return results


def read_oids_from_file(file_path):
    """
    Parses an OID file into a dictionary where keys are descriptive names and values are OIDs.
    Args:
        file_path (str): Path to the OID file.

    Returns:
        dict: A dictionary with descriptive names as keys and OIDs as values.
    """
    if not os.path.exists(file_path):
        logger.error(f"OID file not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")

    oids = {}
    with open(file_path, "r") as file:
        for line in file:
            if "=" in line:
                key, oid = line.strip().split("=", 1)
                oids[key.strip()] = oid.strip()

    logger.info(f"Parsed OIDs: {oids}")
    return oids


def display_results(results):
    """
    Displays the SNMP results in a tabular format using PrettyTable.

    Args:
        results (dict): A dictionary with OID descriptions as keys and fetched values as values.
    """
    # Static left-hand side values
    static_fields = [
        ("Contact", "sysContact"),
        ("Name", "sysName"),
        ("Location", "sysLocation"),
        ("Number", "ifNumber"),
        ("Uptime", "sysUptime"),
    ]

    # Initialize a PrettyTable object
    table = PrettyTable()
    table.field_names = ["Description", "Value"]  # Set the column headers

    # Add rows dynamically with static left-hand values and dynamic results
    for description, oid_key in static_fields:
        value = results.get(
            oid_key, "N/A"
        )  # Fetch value from the results or default to "N/A"
        table.add_row([description, value])

    # Customize the appearance (optional)
    table.align = "l"  # Left-align the content
    table.border = True
    table.header = True

    # Display the table
    print(table)


def main():
    """
    Main function to parse arguments, fetch SNMP data, and display it in a table.
    """
    args = argparse_helper()
    ip = args.ip
    version = args.version
    oid_file = args.oid_file

    # Read OIDs from file
    oids = read_oids_from_file(oid_file)

    # Handle SNMPv1/v2c
    if version in ["1", "2c"]:
        if not args.community:
            logger.error("Community string is required for SNMPv1 and SNMPv2c.")
            exit(1)
        snmp_data = fetch_snmp_data(ip, version, oids, community=args.community)

    # Handle SNMPv3
    elif version == "3":
        snmpv3_params = {
            "username": args.username,
            "sec_level": args.sec_level,
            "auth_protocol": args.auth_protocol,
            "auth_password": args.auth_password,
            "priv_protocol": args.priv_protocol,
            "priv_password": args.priv_password,
        }
        # Validate required SNMPv3 parameters
        if not snmpv3_params["username"] or not snmpv3_params["sec_level"]:
            logger.error("Username and security level are required for SNMPv3.")
            exit(1)
        if snmpv3_params["sec_level"] in ["authNoPriv", "authPriv"]:
            if not snmpv3_params["auth_protocol"] or not snmpv3_params["auth_password"]:
                logger.error(
                    "Authentication protocol and password are required for authNoPriv or authPriv."
                )
                exit(1)
        if snmpv3_params["sec_level"] == "authPriv":
            if not snmpv3_params["priv_protocol"] or not snmpv3_params["priv_password"]:
                logger.error("Privacy protocol and password are required for authPriv.")
                exit(1)

        snmp_data = fetch_snmp_data(ip, version, oids, snmpv3_params=snmpv3_params)

    # Display results
    display_results(snmp_data)


if __name__ == "__main__":
    main()
