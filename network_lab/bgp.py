import json
import re
from prettytable import PrettyTable
from loguru import logger


class BGP:
    def __init__(self, file):
        """
        Initializes the BGP class by requiring a configuration file and log level.

        :param file: Path to the BGP configuration JSON file (this must be provided).
        """
        if not file:
            raise ValueError("A configuration file must be provided.")

        self.file = file
        self.routers = {}  # Empty dictionary initially.

    def load_bgp_config(self):
        """Load BGP configuration from a JSON file."""
        logger.debug(f"Attempting to load BGP configuration from {self.file}")
        try:
            with open(self.file, "r") as f:
                data = json.load(f)
                logger.debug("BGP configuration loaded successfully.")
                return data
        except FileNotFoundError:
            logger.error(f"Configuration file {self.file} not found.")
            return {}

    def get_bgp_config(self):
        """Generate BGP configuration commands for routers."""
        if not self.routers:
            logger.debug("BGP configuration not loaded yet. Loading now.")
            self.routers = self.load_bgp_config()

        if not self.routers:
            logger.warning("No routers found in configuration.")
            return []

        result = []

        for bgp_info in self.routers.get("Routers", {}).values():
            bgp_commands = [
                f"router bgp {bgp_info['local_asn']}",
                f"neighbor {bgp_info['neighbor_ip']} remote-as {bgp_info['neighbor_remote_as']}",
            ]
            network_commands = [
                f"network {network} mask 255.255.255.255"
                for network in bgp_info.get("NetworkListToAdvertise", [])
            ]
            bgp_commands.extend(network_commands)
            result.append(bgp_commands)

        logger.info("BGP configuration generated successfully.")
        logger.debug(f"Generated BGP configuration is {result}")

        return result

    def execute_command(self, net_connect, command):
        """Executes a command on the router and returns the output, or None if invalid input detected."""
        try:
            output = net_connect.send_command(command)
            # Check if invalid input detected in the output
            if "% Invalid input detected at '^' marker." in output:
                logger.error(f"Invalid input detected for command: {command}")
                return None
            return output
        except Exception as e:
            logger.error(f"Command execution failed: {command} - Error: {e}")
            return None

    def bgp_neighbors_status(self, net_connect, router_name):
        """Fetch and display BGP neighbor status."""
        logger.info(f"Checking BGP neighbor status for {router_name}")
        output = self.execute_command(
            net_connect, "show ip bgp neighbors | include BGP"
        )

        if output:
            if "% BGP not active" in output:
                logger.warning(f"BGP not configured or not active on {router_name}")
                print(f"BGP not configured or not active on {router_name}")
                return

            lines = output.splitlines()

            if len(lines) >= 3:
                bgp_neighbor_ip, bgp_neighbor_as, bgp_neighbor_state = (
                    lines[0].split()[3].strip(","),
                    lines[0].split()[6].strip(","),
                    lines[2].split()[3].strip(","),
                )

                table = PrettyTable()
                table.field_names = [
                    "BGP Neighbor IP",
                    "BGP Neighbor AS",
                    "BGP Neighbor State",
                ]
                table.add_row([bgp_neighbor_ip, bgp_neighbor_as, bgp_neighbor_state])

                logger.success(f"Retrieved BGP neighbor status for {router_name}")

                print(router_name)
                print(table)
                print()
            else:
                logger.warning(f"Unexpected BGP output format for {router_name}")
        else:
            logger.error(f"Failed to retrieve BGP neighbor status for {router_name}")

    def bgp_route_info(self, net_connect, router_name):
        """Fetch and display BGP route information."""
        logger.info(f"Fetching BGP route info for {router_name}")
        output = self.execute_command(net_connect, "show ip bgp")

        if output:
            table = PrettyTable()
            table.field_names = ["Network", "Next Hop"]

            for line in output.splitlines():
                if line.startswith("*>"):
                    route_info = line[3:].split()
                    if len(route_info) >= 2:
                        table.add_row([route_info[0], route_info[1]])

            logger.success(f"Retrieved BGP route info for {router_name}")
            print(router_name)
            print(table)
            print()

    def save_running_conf(self, net_connect, router_name):
        """Save the running configuration of a router to a file."""
        logger.info(f"Saving running config for {router_name}")
        output = self.execute_command(net_connect, "show running-config")

        if output:
            file_name = f"{router_name}_running_config.txt"
            with open(file_name, "w") as file:
                file.write(output)
            logger.success(f"Saved running config of {router_name} to {file_name}")

    def update_bgp_state(self, net_connect, router_name):
        """Update BGP neighbor state in the configuration file."""
        if not self.file:
            logger.error("No configuration file provided for update.")
            return

        logger.info(f"Starting BGP state update for router: {router_name}")

        # Execute the command to fetch the BGP neighbor information
        output = self.execute_command(
            net_connect, "show ip bgp neighbors | include BGP"
        )

        if not output:
            logger.error(f"No BGP output received for {router_name}.")
            return

        logger.debug(f"BGP neighbor command output for {router_name}: {output}")

        # Use regex to find the neighbor_state key and its corresponding value
        match = re.search(r"BGP state = (\S+)", output)

        if not match:
            logger.warning(f"Failed to parse 'neighbor_state' for {router_name}.")
            return

        bgp_neighbor_state = match.group(1)
        logger.info(f"Parsed 'neighbor_state' for {router_name}: {bgp_neighbor_state}")

        # Check if the router exists in the configuration
        router_key = next(
            (
                key
                for key, val in self.routers.get("Routers", {}).items()
                if key == router_name
            ),
            None,
        )

        if not router_key:
            logger.warning(f"Router {router_name} not found in configuration.")
            return

        # Update the router's BGP state in the configuration
        self.routers["Routers"][router_key]["neighbor_state"] = bgp_neighbor_state
        logger.info(f"Updated BGP neighbor state for {router_name}.")

        # Save the updated configuration to the file
        try:
            with open(self.file, "w") as f:
                json.dump(self.routers, f, indent=4)
            logger.success(
                f"Successfully updated the BGP configuration file for {router_name}"
            )
        except Exception as e:
            logger.error(f"Failed to write the configuration file: {e}")
