#!/usr/bin/env python3

try:
    import argparse
    import os
    import subprocess
    from prettytable import PrettyTable
    from loguru import logger
except ModuleNotFoundError as e:
    missing_module = str(e).split("'")[1]
    print(f"Error: The module '{missing_module}' is not installed.")
    print(f"Please install it using 'pip install {missing_module}' and try again.")
    exit(1)


def get_unique_filename(filename):
    """
    Ensure the file name is unique by appending a number if the file already exists.

    Args:
        filename (str): Initial file name.

    Returns:
        str: Unique file name.
    """
    base, ext = os.path.splitext(filename)
    counter = 1
    unique_filename = filename

    while os.path.exists(unique_filename):
        unique_filename = f"{base}_{counter}{ext}"
        counter += 1

    return unique_filename


def parse_arguments():
    """
    Parse command-line arguments for the ping sweep script.

    Returns:
        Namespace: Parsed arguments containing the CIDR and output file path.
    """
    parser = argparse.ArgumentParser(
        description="Perform a ping sweep on a network using CIDR notation."
    )
    parser.add_argument(
        "-i",
        "--ip",
        required=True,
        type=str,
        help="CIDR notation for the network (e.g., 192.168.1.0/24).",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        default="ping_sweep_results.txt",
        help="Output text file to save the results. Default: ping_sweep_results.txt",
    )

    return parser.parse_args()


def ping_sweep_with_nmap(ip):
    """
    Perform a ping sweep on the provided CIDR range using nmap.

    Args:
        cidr (str): The CIDR notation for the network.

    Returns:
        list: List of reachable IP addresses.
    """
    reachable = []

    logger.info(f"Starting ping sweep on network: {ip} using nmap")

    try:
        # Use subprocess to run nmap for a ping scan
        result = subprocess.run(
            ["nmap", "-sn", ip], capture_output=True, text=True, check=True
        )
        output = result.stdout

        # Parse nmap output to extract IPs
        for line in output.splitlines():
            if "Nmap scan report for" in line:
                ip = line.split()[-1].strip("()")
                reachable.append(ip)

        logger.success(f"Ping sweep completed successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing nmap: {e}")

    return reachable


def save_results(reachable, output_file):
    """
    Save the ping sweep results to a text file in table format.

    Args:
        reachable (list): List of reachable IP addresses.
        output_file (str): Path to the output text file.
    """
    # Create a PrettyTable object
    table = PrettyTable()
    table.field_names = ["IP Address", "Status"]

    # Add rows for reachable IPs
    for ip in reachable:
        table.add_row([ip, "Reachable"])

    # Save the table to a text file
    with open(output_file, "w") as f:
        f.write(str(table))

    logger.info(f"Results saved to {output_file}")


def main():
    """
    Main function to execute the ping sweep script.
    """
    args = parse_arguments()

    # Ensure output file has a unique name if it exists
    output_file = get_unique_filename(args.file)

    # Perform the ping sweep using nmap
    logger.info(f"Performing ping sweep on {args.ip}...")
    reachable = ping_sweep_with_nmap(args.ip)

    # Save the results to a file
    save_results(reachable, output_file)
    logger.info("Ping sweep complete.")


if __name__ == "__main__":
    main()
