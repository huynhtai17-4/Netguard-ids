"""
Secrets Manager Module for NetGuard IDS

This module provides a secure way to manage sensitive information such as API keys,
database passwords, and encryption keys. It supports multiple backends including
environment variables, HashiCorp Vault, and AWS Secrets Manager.
"""

import os
import json
import logging
from typing import Dict, Optional, Any, Union
from functools import lru_cache
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Optional imports for external secret managers
try:
    import hvac  # HashiCorp Vault client
    HAS_HVAC = True
except ImportError:
    HAS_HVAC = False

try:
    import boto3  # AWS SDK
    from botocore.exceptions import ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

class SecretsManager:
    """
    A secure secrets manager for handling sensitive information.
    
    Supports multiple backends:
    - Environment variables
    - HashiCorp Vault
    - AWS Secrets Manager
    - Encrypted local storage
    """
    
    def __init__(
        self, 
        backend: str = "env",
        vault_url: Optional[str] = None,
        vault_token: Optional[str] = None,
        aws_region: Optional[str] = None,
        encryption_key: Optional[str] = None
    ):
        """
        Initialize the Secrets Manager.
        
        Args:
            backend: Secret storage backend ("env", "vault", "aws", or "encrypted_file")
            vault_url: HashiCorp Vault URL (required for vault backend)
            vault_token: HashiCorp Vault token (required for vault backend)
            aws_region: AWS region (required for aws backend)
            encryption_key: Encryption key for encrypted_file backend
        """
        self.backend = backend
        self.logger = logging.getLogger(__name__)
        
        if backend == "vault":
            if not HAS_HVAC:
                raise ImportError("hvac library is required for Vault backend")
            if not vault_url or not vault_token:
                raise ValueError("Vault URL and token are required for Vault backend")
            self.vault_client = hvac.Client(url=vault_url, token=vault_token)
            
        elif backend == "aws":
            if not HAS_BOTO3:
                raise ImportError("boto3 library is required for AWS backend")
            if not aws_region:
                raise ValueError("AWS region is required for AWS backend")
            self.aws_client = boto3.client('secretsmanager', region_name=aws_region)
            
        elif backend == "encrypted_file":
            if not encryption_key:
                raise ValueError("Encryption key is required for encrypted_file backend")
            self.fernet = self._create_fernet(encryption_key)
            self.secrets_file = os.getenv("SECRETS_FILE", "config/secrets.encrypted")
            
        elif backend != "env":
            raise ValueError(f"Unsupported backend: {backend}")
    
    def _create_fernet(self, password: str, salt: bytes = b"netguard_salt") -> Fernet:
        """
        Create a Fernet instance from a password.
        
        Args:
            password: Password to derive the key from
            salt: Salt for key derivation
            
        Returns:
            Fernet instance for encryption/decryption
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    
    def get_secret(self, secret_name: str, default: Optional[Any] = None) -> Optional[Any]:
        """
        Retrieve a secret by name.
        
        Args:
            secret_name: Name of the secret to retrieve
            default: Default value if secret is not found
            
        Returns:
            Secret value or default if not found
        """
        try:
            if self.backend == "env":
                return os.getenv(secret_name, default)
                
            elif self.backend == "vault":
                try:
                    # KV v2
                    response = self.vault_client.secrets.kv.v2.read_secret_version(path=secret_name)
                    return response['data']['data'] if response else default
                except Exception:
                    # Fallback KV v1
                    response = self.vault_client.read(f"secret/data/{secret_name}")
                    return response['data']['data'] if response else default
                
            elif self.backend == "aws":
                response = self.aws_client.get_secret_value(SecretId=secret_name)
                if 'SecretString' in response:
                    secrets = response['SecretString']
                    try:
                        return json.loads(secrets)
                    except json.JSONDecodeError:
                        return secrets
                else:
                    decoded_binary_secret = base64.b64decode(response['SecretBinary'])
                    return json.loads(decoded_binary_secret)
                    
            elif self.backend == "encrypted_file":
                if not os.path.exists(self.secrets_file):
                    return default
                    
                with open(self.secrets_file, 'rb') as f:
                    encrypted_data = f.read()
                    
                decrypted_data = self.fernet.decrypt(encrypted_data)
                secrets = json.loads(decrypted_data.decode())
                return secrets.get(secret_name, default)
                
        except Exception as e:
            self.logger.error(f"Error retrieving secret {secret_name}: {e}")
            return default
            
        return default
    
    @lru_cache(maxsize=32)
    def get_secret_cached(self, secret_name: str, default: Optional[Any] = None) -> Optional[Any]:
        """
        Retrieve a secret with caching.
        
        Args:
            secret_name: Name of the secret to retrieve
            default: Default value if secret is not found
            
        Returns:
            Secret value or default if not found
        """
        return self.get_secret(secret_name, default)
    
    def set_secret(self, secret_name: str, secret_value: Any) -> bool:
        """
        Store a secret.
        
        Args:
            secret_name: Name of the secret to store
            secret_value: Value of the secret to store
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.backend == "env":
                self.logger.warning("Cannot set environment variables at runtime")
                return False
                
            elif self.backend == "vault":
                secret_path = f"secret/data/{secret_name}"
                self.vault_client.write(secret_path, data=secret_value)
                return True
                
            elif self.backend == "aws":
                # AWS secrets need to be stored as strings
                if isinstance(secret_value, (dict, list)):
                    secret_str = json.dumps(secret_value)
                else:
                    secret_str = str(secret_value)
                    
                try:
                    self.aws_client.create_secret(Name=secret_name, SecretString=secret_str)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ResourceExistsException':
                        self.aws_client.update_secret(SecretId=secret_name, SecretString=secret_str)
                    else:
                        raise
                return True
                
            elif self.backend == "encrypted_file":
                # Read existing secrets
                secrets = {}
                if os.path.exists(self.secrets_file):
                    with open(self.secrets_file, 'rb') as f:
                        encrypted_data = f.read()
                    decrypted_data = self.fernet.decrypt(encrypted_data)
                    secrets = json.loads(decrypted_data.decode())
                
                # Update with new secret
                secrets[secret_name] = secret_value
                
                # Encrypt and write back
                encrypted_data = self.fernet.encrypt(json.dumps(secrets).encode())
                os.makedirs(os.path.dirname(self.secrets_file), exist_ok=True)
                with open(self.secrets_file, 'wb') as f:
                    f.write(encrypted_data)
                    
                return True
                
        except Exception as e:
            self.logger.error(f"Error storing secret {secret_name}: {e}")
            return False
            
        return False
    
    def delete_secret(self, secret_name: str) -> bool:
        """
        Delete a secret.
        
        Args:
            secret_name: Name of the secret to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if self.backend == "env":
                self.logger.warning("Cannot delete environment variables at runtime")
                return False
                
            elif self.backend == "vault":
                secret_path = f"secret/data/{secret_name}"
                self.vault_client.delete(secret_path)
                return True
                
            elif self.backend == "aws":
                self.aws_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
                return True
                
            elif self.backend == "encrypted_file":
                if not os.path.exists(self.secrets_file):
                    return True
                    
                # Read existing secrets
                with open(self.secrets_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.fernet.decrypt(encrypted_data)
                secrets = json.loads(decrypted_data.decode())
                
                # Remove the secret
                if secret_name in secrets:
                    del secrets[secret_name]
                    
                    # Encrypt and write back
                    encrypted_data = self.fernet.encrypt(json.dumps(secrets).encode())
                    with open(self.secrets_file, 'wb') as f:
                        f.write(encrypted_data)
                        
                return True
                
        except Exception as e:
            self.logger.error(f"Error deleting secret {secret_name}: {e}")
            return False
            
        return False
    
    def list_secrets(self) -> list:
        """
        List all available secrets.
        
        Returns:
            List of secret names
        """
        try:
            if self.backend == "env":
                # Environment variables are not enumerable in this context
                return []
                
            elif self.backend == "vault":
                response = self.vault_client.list('secret/metadata')
                return response['data']['keys'] if response else []
                
            elif self.backend == "aws":
                response = self.aws_client.list_secrets()
                return [secret['Name'] for secret in response['SecretList']]
                
            elif self.backend == "encrypted_file":
                if not os.path.exists(self.secrets_file):
                    return []
                    
                with open(self.secrets_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.fernet.decrypt(encrypted_data)
                secrets = json.loads(decrypted_data.decode())
                return list(secrets.keys())
                
        except Exception as e:
            self.logger.error(f"Error listing secrets: {e}")
            return []
            
        return []

# Global secrets manager instance
_secrets_manager = None

def get_secrets_manager(
    backend: str = None,
    vault_url: Optional[str] = None,
    vault_token: Optional[str] = None,
    aws_region: Optional[str] = None,
    encryption_key: Optional[str] = None
) -> SecretsManager:
    """
    Get or create the global secrets manager instance.
    
    Args:
        backend: Secret storage backend
        vault_url: HashiCorp Vault URL
        vault_token: HashiCorp Vault token
        aws_region: AWS region
        encryption_key: Encryption key for encrypted_file backend
        
    Returns:
        SecretsManager instance
    """
    global _secrets_manager
    
    if _secrets_manager is None:
        # Default to environment variables if no backend specified
        if backend is None:
            backend = os.getenv("SECRETS_BACKEND", "env")
            
        # Get configuration from environment if not provided
        if vault_url is None:
            vault_url = os.getenv("VAULT_URL")
        if vault_token is None:
            vault_token = os.getenv("VAULT_TOKEN")
        if aws_region is None:
            aws_region = os.getenv("AWS_REGION")
        if encryption_key is None:
            encryption_key = os.getenv("ENCRYPTION_KEY")
            
        _secrets_manager = SecretsManager(
            backend=backend,
            vault_url=vault_url,
            vault_token=vault_token,
            aws_region=aws_region,
            encryption_key=encryption_key
        )
    
    return _secrets_manager

def get_secret(secret_name: str, default: Optional[Any] = None) -> Optional[Any]:
    """
    Convenience function to get a secret.
    
    Args:
        secret_name: Name of the secret to retrieve
        default: Default value if secret is not found
        
    Returns:
        Secret value or default if not found
    """
    return get_secrets_manager().get_secret(secret_name, default)

def get_secret_cached(secret_name: str, default: Optional[Any] = None) -> Optional[Any]:
    """
    Convenience function to get a secret with caching.
    
    Args:
        secret_name: Name of the secret to retrieve
        default: Default value if secret is not found
        
    Returns:
        Secret value or default if not found
    """
    return get_secrets_manager().get_secret_cached(secret_name, default)