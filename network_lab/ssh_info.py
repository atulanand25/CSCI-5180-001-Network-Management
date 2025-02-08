import json
import os
from loguru import logger


def sshInfo(file_path):
    """
    Reads and returns the content of a JSON file containing SSH information.

    Parameters:
        file_path (str): The path to the JSON file.

    Returns:
        dict: Parsed JSON data if the file exists and is valid.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        json.JSONDecodeError: If the file contains invalid JSON.
    """
    if not os.path.exists(file_path):
        logger.error(f"SSHInfo file not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON format in file {file_path}: {e}")
        raise
