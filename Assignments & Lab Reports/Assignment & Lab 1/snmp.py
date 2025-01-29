#!/usr/bin/env python3

try:
    import argparse
    import os
    import smtplib
    import sys
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from loguru import logger
    from scapy.layers.inet import IP
    from scapy.layers.snmp import SNMP
    from scapy.utils import rdpcap
    from prettytable import PrettyTable
except ModuleNotFoundError as e:
    missing_module = str(e).split("'")[1]
    print(f"Error: The module '{missing_module}' is not installed.")
    print(f"Please install it using 'pip install {missing_module}' and try again.")
    exit(1)


def Argparse_Helper():
    # Make the help message
    parser = argparse.ArgumentParser(
        description="This script sends an email after analyzing the SNMP traps from a packet capture."
    )

    parser.add_argument(
        "-e",
        "--email",
        action="store",
        type=str,
        required=True,
        help="Recipient email address where you want to send the results",
    )
    parser.add_argument(
        "-f",
        "--file",
        action="store",
        type=str,
        required=True,
        help="File location of the packet capture",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")

    # Build the object that has all your arguments in it
    args = parser.parse_args()

    return args


def validate_file(file):

    if not os.path.exists(file):
        # Argparse uses the ArgumentTypeError to give a rejection message like:
        # error: argument input: x does not exist
        sys.exit(f"Error: {file} does not exist.")
    return file


def analyze_snmp_traps(pcap_file):
    """
    Analyze the packet capture file for SNMP traps.

    :param pcap_file: Path to the packet capture file
    :return: List of SNMP trap details (as list)
    """
    logger.info(f"Analyzing SNMP traps from file: {pcap_file}")

    try:
        snmp_traps = []
        capture = rdpcap(pcap_file)
        for packet in capture:
            if SNMP in packet:
                # Access SNMP variable-bindings
                varbinds = packet[SNMP].PDU.varbindlist

                for i, varbind in enumerate(varbinds, 1):
                    oid = varbind.oid.oidname
                    value = varbind.value.val
                    trap_info = f"{packet[IP].src},{packet[IP].dst},{oid},{value}"
                    snmp_traps.append(trap_info)
                    logger.debug(f"Captured SNMP Trap: OID {i}: {oid}, Value: {value}")
        return snmp_traps

    except Exception as e:
        logger.error(f"unable to open the pcap file: {e}")


def send_email(recipient_email, snmp_data):
    """
    Send an email with SNMP trap analysis results.

    :param recipient_email: Email address of the recipient
    :param snmp_data: List of SNMP trap details
    """
    logger.info(f"Sending email to {recipient_email}...")

    try:
        sender_email = "atanand25@gmail.com"  # Update with your sender email
        sender_password = "bnuz hiwv rcil tncp"  # Update with your email password

        subject = "SNMP Trap Analysis Results"
        # body = "\n".join(snmp_data) if snmp_data else "No SNMP traps found in the provided packet capture."

        # Initialize the PrettyTable object with column names
        table = PrettyTable(["Source IP", "Destination IP", "OID", "Value"])

        # Example: Loop through your SNMP traps and add them to the table
        for trap in snmp_data:

            # Split the string based on commas
            parts = trap.split(",")

            # Extract source and destination IPs
            src_ip = parts[0]  # First part is the source IP
            dst_ip = parts[1]  # Second part is the destination IP

            # Extract OID and value
            oid = parts[2]  # Third part is the OID
            value = parts[3]  # Fourth part is the value

            # Add the extracted information as a new row in the table
            table.add_row([src_ip, dst_ip, oid, value])

        # Convert the table to a string format
        table_body = table.get_string()

        # Send the table in the email body
        body = (
            table_body
            if snmp_data
            else "No SNMP traps found in the provided packet capture."
        )

        # Create email message
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = recipient_email
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(
            "smtp.gmail.com", 587
        ) as server:  # Update with your SMTP server
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())

        logger.info(f"{body}")
        logger.success("Email sent successfully.")

    except Exception as e:
        logger.error(f"Failed to send email: {e}")


def main():
    # Call the helper function and store the arg object in the local scope:
    args = Argparse_Helper()

    validate_file(args.file)

    # Analyze SNMP traps
    snmp_traps = analyze_snmp_traps(args.file)

    # Send email with SNMP trap details
    send_email(args.email, snmp_traps)


if __name__ == "__main__":
    main()
