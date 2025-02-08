import subprocess
from loguru import logger


class Connectivity:
    def __init__(self, timeout=5):
        """
        Initializes the Connectivity class with a timeout and log level.

        :param timeout: Timeout for ping in seconds (default is 5).
        """
        self.timeout = timeout

    def check_connectivity(self, ip_address):
        """
        Check if a given IP address is reachable by pinging it.

        :param ip_address: The IP address to check connectivity.
        :return: True if reachable, False otherwise.
        """
        logger.debug(
            f"Checking connectivity to {ip_address}..."
        )  # Log the IP address being checked at DEBUG level

        try:
            # Run the ping command and capture its output
            result = subprocess.run(
                ["ping", "-c", "1", ip_address],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                text=True,
            )

            # Log the output of the ping command at DEBUG level
            logger.debug(f"Ping output for {ip_address}:\n{result.stdout}")

            # Check if the ping was successful (i.e., return code 0)
            if result.returncode == 0:
                logger.info(
                    f"Successfully reached {ip_address}."
                )  # Log success at INFO level
                return True
            else:
                logger.error(
                    f"Ping failed for {ip_address}."
                )  # Log failure at ERROR level
                logger.debug(
                    f"Ping error for {ip_address}:\n{result.stderr}"
                )  # Log any error messages at DEBUG level
                return False
        except Exception as e:
            logger.error(
                f"Failed to reach {ip_address}. Error: {str(e)}"
            )  # Log failure at ERROR level
            return False
