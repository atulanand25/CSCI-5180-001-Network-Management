import ipaddress

def validate_ip(ip_address):
    """
    Validates whether the given string is a valid IPv4 address and checks for restricted ranges.

    Parameters:
        ip_address (str): IP address to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        ip = ipaddress.IPv4Address(ip_address)

        # Invalid IP ranges
        if any([ip.is_multicast, ip.is_loopback, ip.is_link_local,
                ip == ipaddress.IPv4Address("255.255.255.255"),
                ip >= ipaddress.IPv4Address("240.0.0.0")]):
            return False

        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False  # Invalid IP format
