import sys
from netmiko import ConnectHandler
from loguru import logger


def configure_device(ip, username, password, commands, config = False):
    """
    Configures a Cisco router to obtain an IP address via DHCP on Interfaces.

    Parameters:
        ip (str): IP address of the router.
        username (str): SSH username.
        password (str): SSH password.
       commands: commands to be executed on the router.
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
        logger.debug(f"SSH connection parameters: ip={ip}, user={username}, password={password}, configs={commands}")

        connection = ConnectHandler(**device)
        connection.enable()

        logger.success(f"SSH login successful to {ip}")

        if config:
            output = connection.send_config_set(commands)
        else:
            output = connection.send_command(commands)

        if "Invalid" in output or "Error" in output:
            logger.error(f"Configuration failed for {ip}: {output}")
        else:
            logger.info(f"Successfully applied configuration to {ip}.")
            logger.debug(f"Commands executed: {commands}")
            logger.debug(f"Command output: {output}")

        connection.disconnect()
        return output
    except Exception as e:
        logger.error(f"Failed to configure {ip}: {e}")
        sys.exit(1)