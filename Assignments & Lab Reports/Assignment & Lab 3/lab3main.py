#!/usr/bin/env python3

try:
    import argparse
    from threading import Thread
    from prettytable import PrettyTable
    from loguru import logger
    from netmiko import ConnectHandler
    from network_lab.connectivity import Connectivity
    from network_lab.validate_ip import validate_ip
    from network_lab.bgp import BGP
    from network_lab.ssh_info import sshInfo

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


def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="BGP Configuration Automation Script")
    parser.add_argument(
        "-f", "--file", required=True, help="Path to SSH info JSON file"
    )
    parser.add_argument(
        "-c", "--bgp_file", required=True, help="Path to BGP config JSON file"
    )
    parser.add_argument(
        "--log",
        type=int,
        choices=[0, 1, 2],
        default=1,
        help="Logging level: 0 (No log), 1 (Info), 2 (Debug)",
    )

    return parser.parse_args()


def dashboard():
    """Displays a function selection dashboard and prompts the user for their choice."""
    # List of functions and their corresponding numbers
    functions = [
        ("Configure BGP", 1),
        ("Show BGP neighbors status", 2),
        ("Show BGP route info", 3),
        ("Save running-config", 4),
        ("Update BGP conf dict", 5),
        ("EXTRA CREDIT - Ping Check", 6),
    ]

    # Create and configure the table
    table = PrettyTable(field_names=["#", "Function"])

    # Add rows to the table
    for func, num in functions:
        table.add_row([num, func])

    # Set alignment for the columns
    table.align["#"] = "r"  # Right align the number column
    table.align["Function"] = "l"  # Left align the function column

    logger.info("Dashboard displayed with available functions.")
    print("\nWelcome to the Dashboard\n-------------------------")
    print(table)

    try:
        # Prompt for valid input
        func_number = int(
            input("\nEnter the function number (1-6) to choose an action: ")
        )
        logger.debug(f"User input: {func_number}")

        if func_number not in dict(functions).values():
            logger.error(
                f"Invalid function number: {func_number}. Please enter a number between 1 and 5."
            )
            return None

        logger.info(f"User selected function number {func_number}.")
        return func_number

    except ValueError:
        logger.error("Invalid input. Please enter a valid number!")
        return None


def sanity_checks(file):
    """Performs preliminary checks on SSH info and IP addresses."""
    ssh_info = sshInfo(file)

    if not ssh_info:
        logger.error("SSH info file doesn't exist")
        return False

    ip_list = [info["ip"] for info in ssh_info.values()]
    connectivity_checker = Connectivity()

    # Check IP validity and connectivity in one loop
    for ip in ip_list:
        if not validate_ip(ip):
            logger.error(f"{ip} is not a valid IP address")
            return False
        if not connectivity_checker.check_connectivity(ip):
            logger.error(f"{ip} is not reachable")
            return False

    return ssh_info


def conf(router_name, ssh_info, option, bgp_commands, bgp_instance):
    """Executes the selected BGP function on the router."""

    try:
        net_connect = ConnectHandler(**ssh_info)
        net_connect.enable()

        if option == 1:
            output = net_connect.send_config_set(bgp_commands)
            if "% Invalid input detected at '^' marker." in output:
                logger.error(f"Configuration error on {router_name}\n{output}")
            else:
                logger.debug(f"Successfully configured {router_name}\n{output}")
                logger.success(f"Successfully configured {router_name}")

        elif option == 2:
            bgp_instance.bgp_neighbors_status(net_connect, router_name)

        elif option == 3:
            bgp_instance.bgp_route_info(net_connect, router_name)

        elif option == 4:
            bgp_instance.save_running_conf(net_connect, router_name)

        elif option == 5:
            bgp_instance.update_bgp_state(net_connect, router_name)

        else:
            logger.error("Invalid function number selected!")

        net_connect.disconnect()

    except Exception as e:
        logger.error(f"Error processing {router_name}: {e}")


def ping_test(router_1, router_2, loopback_ip_r1, loopback_ip_r2):
    """
    EXTRA CREDIT - Verifies connectivity between loopback interfaces of R1 and R2.

    Parameters:
        router_1 (dict): Connection details for R1.
        router_2 (dict): Connection details for R2.
        loopback_ip_r1 (str): Loopback IP address of R1.
        loopback_ip_r2 (str): Loopback IP address of R2.
    """
    try:
        # Connect to R1 and ping R2's loopback IP
        connection_r1 = ConnectHandler(**router_1)
        logger.info(f"Pinging R2's loopback IP {loopback_ip_r2} from R1...")
        ping_result_r1 = connection_r1.send_command(f"ping {loopback_ip_r2}")
        if "Success" in ping_result_r1:
            logger.success(
                f"Ping from R1 {router_1.get('ip')} to R2's loopback IP {loopback_ip_r2} succeeded.\n{ping_result_r1}"
            )
        else:
            logger.error(f"Ping from R1 to R2's loopback IP {loopback_ip_r2} failed.")
        connection_r1.disconnect()

        # Connect to R2 and ping R1's loopback IP
        connection_r2 = ConnectHandler(**router_2)
        logger.info(f"Pinging R1's loopback IP {loopback_ip_r1} from R2...")
        ping_result_r2 = connection_r2.send_command(f"ping {loopback_ip_r1}")
        if "Success" in ping_result_r2:
            logger.success(
                f"Ping from R2 {router_2.get('ip')} to R1's loopback IP {loopback_ip_r1} succeeded.\n{ping_result_r2}"
            )
        else:
            logger.error(f"Ping from R2 to R1's loopback IP {loopback_ip_r1} failed.")
        connection_r2.disconnect()

    except Exception as e:
        logger.error(f"Error during ping test: {e}")


def main():
    """Main function to run the script."""
    args = parse_arguments()
    setup_logger(args.log)
    logger.info(f"Using SSH info file: {args.file}")

    option = dashboard()
    if option is None:
        return

    ssh_info = sanity_checks(args.file)
    if not ssh_info:
        return

    if 1 <= option <= 5:
        bgp_instance = BGP(file="../../network_lab/bgp.conf")  # Instantiate without arguments

        bgp_conf_commands = bgp_instance.get_bgp_config()
        threads = []

        for router, ssh_details, bgp_commands in zip(
            ssh_info.keys(), ssh_info.values(), bgp_conf_commands
        ):
            thread = Thread(
                target=conf,
                args=(router, ssh_details, option, bgp_commands, bgp_instance),
            )
            thread.start()

            threads.append(thread)
            for thread in threads:
                thread.join()

    elif option == 6:

        router = []
        for key in ssh_info.keys():
            router.append(ssh_info.get(key))

        loopback_ip_r1 = f"10.10.10.1"
        loopback_ip_r2 = f"20.20.20.1"
        router_1 = router[0]
        router_2 = router[1]

        ping_test(router_1, router_2, loopback_ip_r1, loopback_ip_r2)


if __name__ == "__main__":
    main()
