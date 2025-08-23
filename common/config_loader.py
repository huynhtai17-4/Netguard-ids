"""
Configuration Loader Module for NetGuard IDS

This module provides a ConfigLoader class for loading and managing configuration
from YAML files and environment variables with support for nested structures.
"""

import os
import yaml
import logging
from typing import Any, Dict, Optional, Union
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

class ConfigLoader:
    """
    A configuration loader that supports YAML files and environment variables.
    
    This class handles loading configuration from YAML files with the ability
    to override values with environment variables. It supports nested configuration
    structures and automatic type conversion.
    
    Attributes:
        config (Dict): The loaded configuration dictionary
        env_prefix (str): Prefix for environment variables
    """
    
    def __init__(self, env_prefix: str = "NETGUARD"):
        """
        Initialize the ConfigLoader.
        
        Args:
            env_prefix (str): Prefix for environment variables
        """
        self.config = {}
        self.env_prefix = env_prefix.upper()
        self.logger = logging.getLogger(__name__)
        
    def load_config(self, config_path: str, env_overrides: bool = True) -> Dict[str, Any]:
        """
        Load configuration from a YAML file.
        
        Args:
            config_path (str): Path to the YAML configuration file
            env_overrides (bool): Whether to apply environment variable overrides
            
        Returns:
            Dict: The loaded configuration dictionary
            
        Raises:
            FileNotFoundError: If the config file doesn't exist
            yaml.YAMLError: If the YAML file is malformed
        """
        # Check if config file exists
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        # Load YAML configuration
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing YAML configuration: {e}")
            raise
        
        # Apply environment variable overrides if requested
        if env_overrides:
            self._apply_env_overrides()
            
        self.logger.info(f"Configuration loaded from {config_path}")
        return self.config
    
    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to the configuration."""
        # Flatten the config to handle nested structures
        flat_config = self._flatten_config(self.config)
        
        # Check each key for environment variable overrides
        for key_path, value in flat_config.items():
            env_var_name = self._key_path_to_env_var(key_path)
            
            # Check if environment variable exists
            if env_var_name in os.environ:
                env_value = os.environ[env_var_name]
                
                # Convert environment variable value to appropriate type
                converted_value = self._convert_value(env_value, value)
                
                # Update the configuration
                self._set_nested_value(key_path, converted_value)
                
                self.logger.info(f"[ENV OVERRIDE] {key_path} <- {env_var_name} = {converted_value}")
    
    def _flatten_config(self, config: Dict, parent_key: str = '') -> Dict[str, Any]:
        """
        Flatten a nested configuration dictionary.
        
        Args:
            config (Dict): The configuration dictionary to flatten
            parent_key (str): The parent key path (used for recursion)
            
        Returns:
            Dict: A flattened dictionary with dot-separated keys
        """
        items = {}
        for key, value in config.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            
            if isinstance(value, dict):
                # Recursively flatten nested dictionaries
                items.update(self._flatten_config(value, new_key))
            else:
                items[new_key] = value
                
        return items
    
    def _key_path_to_env_var(self, key_path: str) -> str:
        """
        Convert a dot-separated key path to an environment variable name.
        
        Args:
            key_path (str): Dot-separated key path (e.g., 'agent.capture.interface')
            
        Returns:
            str: Environment variable name (e.g., 'NETGUARD_AGENT_CAPTURE_INTERFACE')
        """
        # Convert to uppercase and replace dots with underscores
        env_var = key_path.upper().replace('.', '_')
        return f"{self.env_prefix}_{env_var}"
    
    def _convert_value(self, env_value: str, original_value: Any) -> Any:
        """
        Convert environment variable string to appropriate type based on original value.
        
        Args:
            env_value (str): The environment variable value as string
            original_value (Any): The original value from config for type reference
            
        Returns:
            Any: The converted value with appropriate type
        """
        # Handle None values
        if original_value is None:
            return env_value
            
        # Handle boolean values
        if isinstance(original_value, bool):
            return env_value.lower() in ('true', 'yes', '1', 'on')
        
        # Handle integer values
        elif isinstance(original_value, int):
            try:
                return int(env_value)
            except ValueError:
                self.logger.warning(f"Could not convert {env_value} to int, using original value")
                return original_value
        
        # Handle float values
        elif isinstance(original_value, float):
            try:
                return float(env_value)
            except ValueError:
                self.logger.warning(f"Could not convert {env_value} to float, using original value")
                return original_value
        
        # Handle list values (comma-separated)
        elif isinstance(original_value, list):
            if env_value.startswith('[') and env_value.endswith(']'):
                # Handle JSON-like array format
                try:
                    import json
                    return json.loads(env_value)
                except json.JSONDecodeError:
                    self.logger.warning(f"Could not parse JSON list {env_value}, using original value")
                    return original_value
            else:
                # Handle comma-separated values
                return [item.strip() for item in env_value.split(',')]
        
        # Handle dictionary values (JSON format)
        elif isinstance(original_value, dict):
            try:
                import json
                return json.loads(env_value)
            except json.JSONDecodeError:
                self.logger.warning(f"Could not parse JSON dictionary {env_value}, using original value")
                return original_value
        
        # Default to string
        else:
            return env_value
    
    def _set_nested_value(self, key_path: str, value: Any) -> None:
        """
        Set a value in a nested dictionary using a dot-separated key path.
        
        Args:
            key_path (str): Dot-separated key path (e.g., 'agent.capture.interface')
            value (Any): The value to set
        """
        keys = key_path.split('.')
        config_ptr = self.config
        
        # Navigate to the nested key
        for key in keys[:-1]:
            if key not in config_ptr:
                config_ptr[key] = {}
            config_ptr = config_ptr[key]
        
        # Set the value
        config_ptr[keys[-1]] = value
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a configuration value using a dot-separated key path.
        
        Args:
            key_path (str): Dot-separated key path (e.g., 'agent.capture.interface')
            default (Any): Default value if key doesn't exist
            
        Returns:
            Any: The configuration value or default
        """
        keys = key_path.split('.')
        config_ptr = self.config
        
        try:
            for key in keys:
                config_ptr = config_ptr[key]
            return config_ptr
        except (KeyError, TypeError):
            return default
    
    def get_section(self, section: str) -> Dict:
        """
        Get a configuration section.
        
        Args:
            section (str): The section name
            
        Returns:
            Dict: The configuration section or empty dict if not found
        """
        return self.config.get(section, {})
    
    def reload(self, config_path: str) -> Dict[str, Any]:
        """
        Reload the configuration from file.
        
        Args:
            config_path (str): Path to the YAML configuration file
            
        Returns:
            Dict: The reloaded configuration dictionary
        """
        return self.load_config(config_path)
    
    def update(self, updates: Dict[str, Any]) -> None:
        """
        Update configuration with new values.
        
        Args:
            updates (Dict): Dictionary of updates to apply
        """
        for key_path, value in updates.items():
            self._set_nested_value(key_path, value)
    
    def save(self, config_path: str) -> None:
        """
        Save the current configuration to a YAML file.
        
        Args:
            config_path (str): Path to save the configuration file
            
        Raises:
            IOError: If the file cannot be written
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            with open(config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
                
            self.logger.info(f"Configuration saved to {config_path}")
        except IOError as e:
            self.logger.error(f"Error saving configuration: {e}")
            raise

# Singleton instance for easy access
_config_loader = ConfigLoader()

def get_config_loader(env_prefix: str = "NETGUARD") -> ConfigLoader:
    """
    Get the singleton ConfigLoader instance.
    
    Args:
        env_prefix (str): Prefix for environment variables
        
    Returns:
        ConfigLoader: The ConfigLoader instance
    """
    global _config_loader
    if env_prefix != "NETGUARD":
        _config_loader = ConfigLoader(env_prefix)
    return _config_loader

def load_config(config_path: str, env_prefix: str = "NETGUARD", env_overrides: bool = True) -> Dict[str, Any]:
    """
    Convenience function to load configuration.
    
    Args:
        config_path (str): Path to the YAML configuration file
        env_prefix (str): Prefix for environment variables
        env_overrides (bool): Whether to apply environment variable overrides
        
    Returns:
        Dict: The loaded configuration dictionary
    """
    loader = get_config_loader(env_prefix)
    return loader.load_config(config_path, env_overrides)

def get_config_value(key_path: str, default: Any = None) -> Any:
    """
    Convenience function to get a configuration value.
    
    Args:
        key_path (str): Dot-separated key path
        default (Any): Default value if key doesn't exist
        
    Returns:
        Any: The configuration value or default
    """
    return _config_loader.get(key_path, default)

def get_config_section(section: str) -> Dict:
    """
    Convenience function to get a configuration section.
    
    Args:
        section (str): The section name
        
    Returns:
        Dict: The configuration section or empty dict if not found
    """
    return _config_loader.get_section(section)