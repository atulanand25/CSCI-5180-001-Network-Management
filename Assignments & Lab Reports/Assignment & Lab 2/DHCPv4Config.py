#!/usr/bin/env python3

try:
    import re
    import argparse
    import sys
    from netmiko import ConnectHandler
    from loguru import logger
    from threading import Thread
except ModuleNotFoundError as e:
    missing_module = str(e).split("'")[1]
    print(f"Error: The module '{missing_module}' is not installed.")
    print(f"Please install it using 'pip install {missing_module}' and try again.")
    exit(1)


def setup_logger(log_level):
    """
    Configures the logging level dynamically based on user input.

    Parameters:
        log_level (int): Logging level (0 - No log, 1 - Info, 2 - Debug).
    """
    logger.remove()
    if log_level == 1:
        logger.add(lambda msg: print(msg, end=""), level="INFO")
    elif log_level == 2:
        logger.add(lambda msg: print(msg, end=""), level="DEBUG")


def argparse_helper():
    """
    Parses command-line arguments required for configuring Cisco routers.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Configure interfaces to receive IP from DHCP on Cisco routers."
    )
    parser.add_argument(
        "-i",
        "--ip",
        type=str,
        required=True,
        help="IP address or range (e.g., 10.0.10.1-3)",
    )
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument(
        "--log",
        type=int,
        choices=[0, 1, 2],
        default=1,
        help="Logging level: 0 (No log), 1 (Info), 2 (Debug)",
    )
    return parser.parse_args()


def is_valid_ip(ip):
    """
    Validates whether the given string is a valid IPv4 address.

    Parameters:
        ip (str): IP address to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    pattern = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    return bool(re.match(pattern, ip))


def parse_ip_range(ip_range):
    """
    Parses an IP range and returns a list of individual IP addresses.

    Parameters:
        ip_range (str): IP range in the format '10.0.10.1-3'.

    Returns:
        list: List of parsed IP addresses.

    Raises:
        ValueError: If the IP range is invalid.
    """
    match = re.fullmatch(r"(\d+\.\d+\.\d+)\.(\d+)-(\d+)", ip_range)
    if match:
        base, start, end = match.groups()
        start, end = int(start), int(end)
        if start > end or not (0 <= start <= 255 and 0 <= end <= 255):
            raise ValueError(f"Invalid IP range: {ip_range}")
        return [f"{base}.{i}" for i in range(start, end + 1)]
    return [ip_range]


def configure_device(ip, username, password):
    """
    Configures a Cisco router to obtain an IP address via DHCP on Interfaces.

    Parameters:
        ip (str): IP address of the router.
        username (str): SSH username.
        password (str): SSH password.
    """
    device = {
        "device_type": "cisco_ios",
        "ip": ip,
        "username": username,
        "password": password,
        "secret": password,
    }
    try:
        logger.info(f"Attempting SSH login to {ip}")
        logger.debug(f"SSH connection parameters: user={username}, password={password}")

        connection = ConnectHandler(**device)
        connection.enable()

        logger.success(f"SSH login successful to {ip}")

        config_commands = [
            "interface fastEthernet 1/0",
            "ip address dhcp",
            "no shutdown",
        ]
        output = connection.send_config_set(config_commands)

        if "Invalid" in output or "Error" in output:
            logger.error(f"Configuration failed for {ip}: {output}")
        else:
            logger.info(f"Successfully applied configuration to {ip}.")
            logger.debug(f"Commands executed: {config_commands}")
            logger.debug(f"Command output: {output}")

        logger.info(f"Router {ip} configured for DHCP.")
        connection.disconnect()
    except Exception as e:
        logger.error(f"Failed to configure {ip}: {e}")
        sys.exit(1)


def main():
    """
    Main function to parse arguments, validate IPs, and configure Cisco routers in parallel using threading.
    """
    args = argparse_helper()
    setup_logger(args.log)
    try:
        ip_list = parse_ip_range(args.ip)
        threads = []
        for ip in ip_list:
            if not is_valid_ip(ip):
                raise ValueError(
                    f"Invalid IP: {ip}. Please enter a valid IP or correct the range."
                )
            logger.info(f"Launching thread for {ip}")
            thread = Thread(
                target=configure_device, args=(ip, args.user, args.password)
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
