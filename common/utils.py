"""
Utility Module for NetGuard IDS

This module provides common utility functions used throughout the NetGuard IDS system,
including time handling, IP address manipulation, data conversion, and other helpers.
"""
import math
import re
import ipaddress
import socket
import struct
import time
import datetime
from typing import Union, List, Tuple, Optional, Any, Dict
from functools import wraps

def get_current_timestamp() -> float:
    """
    Get the current timestamp in seconds since the epoch as a float.
    
    Returns:
        Current timestamp with high precision
    """
    return time.time()

def format_timestamp(timestamp: float, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format a timestamp into a human-readable string.
    
    Args:
        timestamp: Timestamp in seconds since the epoch
        fmt: Format string (default: ISO-like format)
        
    Returns:
        Formatted datetime string
    """
    return datetime.datetime.fromtimestamp(timestamp).strftime(fmt)

def datetime_to_timestamp(dt: datetime.datetime) -> float:
    """
    Convert a datetime object to a timestamp.
    
    Args:
        dt: Datetime object to convert
        
    Returns:
        Timestamp in seconds since the epoch
    """
    return dt.timestamp()

def is_valid_ip(ip_str: str) -> bool:
    """
    Check if a string is a valid IPv4 or IPv6 address.
    
    Args:
        ip_str: String to validate as an IP address
        
    Returns:
        True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_valid_cidr(cidr_str: str) -> bool:
    """
    Check if a string is a valid CIDR notation.
    
    Args:
        cidr_str: String to validate as CIDR notation
        
    Returns:
        True if valid CIDR, False otherwise
    """
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False

def ip_to_int(ip_str: str) -> int:
    """
    Convert an IP address string to an integer.
    
    Args:
        ip_str: IP address string (IPv4 or IPv6)
        
    Returns:
        Integer representation of the IP address
        
    Raises:
        ValueError: If the IP address is invalid
    """
    if not is_valid_ip(ip_str):
        raise ValueError(f"Invalid IP address: {ip_str}")
    
    return int(ipaddress.ip_address(ip_str))

def int_to_ip(ip_int: int, version: Optional[int] = None) -> str:
    """
    Convert an integer to an IP address string.
    
    Args:
        ip_int: Integer representation of an IP address
        version: IP version (4 or 6)
        
    Returns:
        IP address string
        
    Raises:
        ValueError: If version is not 4 or 6
    """
    if version == 4:
        return str(ipaddress.IPv4Address(ip_int))
    elif version == 6:
        return str(ipaddress.IPv6Address(ip_int))
    elif version is None:
        return str (ipaddress.ip_address(ip_int))
    else:
        raise ValueError("IP version must be 4, 6, or None")

def is_private_ip(ip_str: str) -> bool:
    """
    Check if an IP address is in a private range.
    
    Args:
        ip_str: IP address string to check
        
    Returns:
        True if the IP is private, False otherwise
        
    Raises:
        ValueError: If the IP address is invalid
    """
    if not is_valid_ip(ip_str):
        raise ValueError(f"Invalid IP address: {ip_str}")
    
    ip = ipaddress.ip_address(ip_str)
    return ip.is_private

def is_ip_in_network(ip_str: str, network_str: str) -> bool:
    """
    Check if an IP address is within a network range.
    
    Args:
        ip_str: IP address string to check
        network_str: Network in CIDR notation
        
    Returns:
        True if the IP is in the network, False otherwise
        
    Raises:
        ValueError: If the IP address or network is invalid
    """
    if not is_valid_ip(ip_str):
        raise ValueError(f"Invalid IP address: {ip_str}")
    
    if not is_valid_cidr(network_str):
        raise ValueError(f"Invalid network: {network_str}")
    
    ip = ipaddress.ip_address(ip_str)
    network = ipaddress.ip_network(network_str, strict=False)
    
    return ip in network

def mac_address_format(mac_str: str, separator: str = ":", uppercase: bool = False) -> str:
    """
    Format a MAC address to a standard format.
    
    Args:
        mac_str: MAC address string in any format
        separator: Separator to use between bytes (default: ":")
        
    Returns:
        Formatted MAC address
        
    Raises:
        ValueError: If the MAC address is invalid
    """
    # Remove any non-hex characters
    clean_mac = "".join(c for c in mac_str if c.isalnum())
    
    # Check if we have exactly 12 hex characters
    if len(clean_mac) != 12:
        raise ValueError(f"Invalid MAC address: {mac_str}")
    
    # Format with separator
    mac = separator.join(clean_mac[i:i + 2] for i in range(0, 12, 2))
    return mac.upper() if uppercase else mac.lower()

def human_readable_bytes(size_bytes: int) -> str:
    """
    Convert a size in bytes to a human-readable string.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Human-readable size string
    """
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    size = float(size_bytes)
    
    while size >= 1024 and i < len(size_names) - 1:
        size /= 1024
        i += 1
        
    return f"{size:.2f} {size_names[i]}"

def parse_timedelta(time_str: str) -> datetime.timedelta:
    """
    Parse a time duration string into a timedelta object.
    
    Supports formats like:
    - "1h" (1 hour)
    - "30m" (30 minutes)
    - "2h30m" (2 hours 30 minutes)
    - "1d" (1 day)
    
    Args:
        time_str: Time duration string
        
    Returns:
        Timedelta object
        
    Raises:
        ValueError: If the time string format is invalid
    """
    time_units = {
        's': 'seconds',
        'm': 'minutes',
        'h': 'hours',
        'd': 'days',
        'w': 'weeks'
    }
    
    pattern = re.compile(r'(\d+)([smhdw])')
    matches = pattern.findall(time_str)
    
    if not matches:
        raise ValueError(f"Invalid time format: {time_str}")
    
    kwargs = {}
    for value, unit in matches:
        kwargs[time_units[unit]] = int(value)
        
    return datetime.timedelta(**kwargs)

def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0,
          exceptions: Tuple = (Exception,)):
    """
    Decorator for retrying a function with exponential backoff.
    
    Args:
        max_attempts: Maximum number of attempts
        delay: Initial delay between attempts in seconds
        backoff: Backoff multiplier
        exceptions: Tuple of exceptions to catch and retry on
        
    Returns:
        Decorated function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            current_delay = delay
            
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempts += 1
                    if attempts == max_attempts:
                        raise e
                    print(f"[retry] {func.__name__} failed ({e}), attempt {attempts}/{max_attempts}, retrying in {current_delay:.1f}s...")
                    time.sleep(current_delay)
                    current_delay *= backoff
                    
            return func(*args, **kwargs)
        return wrapper
    return decorator

def deep_merge(dict1: Dict, dict2: Dict) -> Dict:
    """
    Recursively merge two dictionaries.
    
    Values from dict2 override values in dict1.
    Nested dictionaries are merged recursively.
    
    Args:
        dict1: Base dictionary
        dict2: Dictionary to merge into dict1
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if (key in result and isinstance(result[key], dict) and 
            isinstance(value, dict)):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
            
    return result

def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """
    Split a list into chunks of a specified size.
    
    Args:
        lst: List to chunk
        chunk_size: Size of each chunk
        
    Returns:
        List of chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def safe_get(dictionary: Dict, keys: List, default: Any = None) -> Any:
    """
    Safely get a value from a nested dictionary.
    
    Args:
        dictionary: Dictionary to search
        keys: List of keys representing the path to the value
        default: Default value to return if the path doesn't exist
        
    Returns:
        Value at the specified path or default value
    """
    current = dictionary
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current

def validate_port(port: Union[int, str]) -> bool:
    """
    Validate a port number.
    
    Args:
        port: Port number to validate
        
    Returns:
        True if valid port, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def normalize_protocol(protocol: Union[int, str]) -> int:
    """
    Normalize a protocol to its numeric representation.
    
    Args:
        protocol: Protocol name or number
        
    Returns:
        Protocol number
        
    Raises:
        ValueError: If the protocol is invalid
    """
    if isinstance(protocol, int):
        if 0 <= protocol <= 255:
            return protocol
        else:
            raise ValueError(f"Invalid protocol number: {protocol}")
    
    protocol_str = str(protocol).lower()
    
    # Common protocol mappings
    protocol_map = {
        'icmp': 1,
        'tcp': 6,
        'udp': 17,
        'ipv6-icmp': 58
    }
    
    if protocol_str in protocol_map:
        return protocol_map[protocol_str]
    
    # Try to convert to integer
    try:
        protocol_num = int(protocol_str)
        if 0 <= protocol_num <= 255:
            return protocol_num
        else:
            raise ValueError(f"Invalid protocol number: {protocol}")
    except ValueError:
        raise ValueError(f"Unknown protocol: {protocol}")

def calculate_entropy(data: Union[str, bytes]) -> float:
    """
    Calculate the Shannon entropy of a string or bytes.
    
    Args:
        data: Input data
        
    Returns:
        Entropy value
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if not data:
        return 0.0
    
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
            
    return entropy

def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain name.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if valid domain, False otherwise
    """
    if not domain or len(domain) > 253:
        return False
    
    # Check each label
    labels = domain.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', label, re.IGNORECASE):
            return False
            
    return True

def timeit(func):
    """
    Decorator to measure the execution time of a function.
    
    Args:
        func: Function to time
        
    Returns:
        Decorated function
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"{func.__name__} executed in {end_time - start_time:.4f} seconds")
        return result
    return wrapper

class Timer:
    """
    A context manager for timing code blocks.
    """
    def __enter__(self):
        self.start = time.time()
        return self
        
    def __exit__(self, *args):
        self.end = time.time()
        self.interval = self.end - self.start
        
    def __str__(self):
        return f"{self.interval:.4f} seconds"