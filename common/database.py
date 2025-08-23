"""
Database Module for NetGuard IDS

This module provides a Database class for managing SQLAlchemy connections,
sessions, and database operations with connection pooling and retry mechanisms.
"""

import logging
from typing import Optional, Any, Dict, Generator
from contextlib import contextmanager
from sqlalchemy import text
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, scoped_session, Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError, OperationalError, DisconnectionError
from sqlalchemy.pool import QueuePool

# Import utilities
from common.config_loader import get_config_value
from common.logger import get_logger
from common.utils import retry

# Create declarative base
Base = declarative_base()

class Database:
    """
    Database management class for SQLAlchemy connections and sessions.
    
    This class handles database connection pooling, session management,
    and provides retry mechanisms for database operations.
    """
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern to ensure only one database instance exists."""
        if cls._instance is None:
            cls._instance = super(Database, cls).__new__(cls)
        return cls._instance
    
    def __init__(
        self, 
        connection_string: Optional[str] = None,
        pool_size: int = 10,
        max_overflow: int = 20,
        pool_timeout: int = 30,
        pool_recycle: int = 3600,
        echo: bool = False
    ):
        """
        Initialize the database connection.
        
        Args:
            connection_string: SQLAlchemy connection string
            pool_size: Number of connections to keep in the pool
            max_overflow: Maximum number of connections beyond pool_size
            pool_timeout: Timeout for getting a connection from the pool
            pool_recycle: Recycle connections after this many seconds
            echo: Whether to echo SQL statements (for debugging)
        """
        if hasattr(self, '_initialized'):
            return
            
        self.logger = get_logger()
        
        # Get connection string from config if not provided
        if connection_string is None:
            connection_string = get_config_value("dashboard.database.connection_string")
            if connection_string is None:
                raise ValueError("Database connection string is required")
        
        self.connection_string = connection_string
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_recycle = pool_recycle
        self.echo = echo
        
        # Initialize engine and session factory
        self.engine = None
        self.session_factory = None
        self.ScopedSession = None
        
        self._initialize_engine()
        self._initialize_session_factory()
        
        self._initialized = True
        self.logger.info("Database initialized successfully")
    
    def _initialize_engine(self) -> None:
        """Initialize the SQLAlchemy engine with connection pooling."""
        try:
            # Create engine with connection pooling
            self.engine = create_engine(
                self.connection_string,
                poolclass=QueuePool,
                pool_size=self.pool_size,
                max_overflow=self.max_overflow,
                pool_timeout=self.pool_timeout,
                pool_recycle=self.pool_recycle,
                echo=self.echo,
                # SQLite specific configuration
                connect_args={"check_same_thread": False} 
                if "sqlite" in self.connection_string else {}
            )
            
            # Add connection validation
            self._add_connection_validation()
            
            self.logger.debug("Database engine initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database engine: {e}")
            raise
    
    def _add_connection_validation(self) -> None:
        """Add connection validation to the engine."""
        # For PostgreSQL and MySQL, add ping connection validation
        if "postgresql" in self.connection_string or "mysql" in self.connection_string:
            @event.listens_for(self.engine, "engine_connect")
            def ping_connection(connection, branch):
                if branch:
                    # "branch" refers to a sub-connection of a connection,
                    # we don't want to bother pinging on these.
                    return
                
                # Turn off the close-with-result flag for this connection
                save_should_close_with_result = connection.should_close_with_result
                connection.should_close_with_result = False
                
                try:
                    # Run a simple SELECT 1 to check the connection
                    connection.scalar("SELECT 1")
                except OperationalError:
                    # Catch OperationalError and try to reconnect
                    raise DisconnectionError()
                finally:
                    # Restore the close-with-result flag
                    connection.should_close_with_result = save_should_close_with_result
    
    def _initialize_session_factory(self) -> None:
        """Initialize the session factory."""
        try:
            self.session_factory = sessionmaker(
                bind=self.engine,
                autocommit=False,
                autoflush=False,
                expire_on_commit=False
            )
            
            # Create a scoped session for thread safety
            self.ScopedSession = scoped_session(self.session_factory)
            
            self.logger.debug("Session factory initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize session factory: {e}")
            raise
    
    @contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """
        Provide a transactional scope around a series of operations.
        
        Yields:
            SQLAlchemy session object
            
        Raises:
            SQLAlchemyError: If any database operation fails
        """
        session = self.ScopedSession()
        try:
            yield session
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            session.close()
            self.ScopedSession.remove()
    
    @retry(max_attempts=3, delay=1.0, backoff=2.0, exceptions=(OperationalError,))
    def execute_query(self, query: Any, **kwargs: Any) -> Any:
        """
        Execute a raw SQL query with retry mechanism.
        
        Args:
            query: SQL query to execute
            **kwargs: Additional arguments for the query
            
        Returns:
            Result of the query execution
        """
        with self.engine.connect() as connection:
            result = connection.execute(query, **kwargs)
            return result
    
    def create_tables(self) -> None:
        """
        Create all tables defined in the models.
        
        This should be called after all models are imported.
        """
        try:
            Base.metadata.create_all(self.engine)
            self.logger.info("Database tables created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create database tables: {e}")
            raise
    
    def drop_tables(self) -> None:
        """
        Drop all tables defined in the models.
        
        Warning: This will delete all data in the database.
        """
        try:
            Base.metadata.drop_all(self.engine)
            self.logger.warning("Database tables dropped")
        except Exception as e:
            self.logger.error(f"Failed to drop database tables: {e}")
            raise
    
    def get_engine(self) -> Engine:
        """
        Get the SQLAlchemy engine.
        
        Returns:
            SQLAlchemy engine instance
        """
        return self.engine
    
    def get_session(self) -> Session:
        """
        Get a new database session.
        
        Returns:
            New SQLAlchemy session
            
        Note: You are responsible for closing the session after use.
        """
        return self.ScopedSession()
    
    def close(self) -> None:
        """Close all database connections and cleanup."""
        if self.engine:
            self.engine.dispose()
            self.logger.info("Database connections closed")
    
    def health_check(self) -> bool:
        """
        Perform a health check on the database connection.
        
        Returns:
            True if the database is accessible, False otherwise
        """
        try:
            with self.engine.connect() as connection:
                result = connection.scalar("SELECT 1")
                return result == 1
        except Exception as e:
            self.logger.error(f"Database health check failed: {e}")
            return False
    
    def get_connection_info(self) -> Dict[str, Any]:
        """
        Get information about the database connection.
        
        Returns:
            Dictionary with connection information
        """
        return {
            "dialect": self.engine.dialect.name,
            "driver": self.engine.dialect.driver,
            "pool_size": self.engine.pool.size(),
            "checked_out": self.engine.pool.checkedout(),
            "checked_in": self.engine.pool.checkedin(),
            "overflow": self.engine.pool.overflow(),
        }

# Global database instance
_database_instance = None

def get_database(
    connection_string: Optional[str] = None,
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_timeout: int = 30,
    pool_recycle: int = 3600,
    echo: bool = False
) -> Database:
    """
    Get or create the global database instance.
    
    Args:
        connection_string: SQLAlchemy connection string
        pool_size: Number of connections to keep in the pool
        max_overflow: Maximum number of connections beyond pool_size
        pool_timeout: Timeout for getting a connection from the pool
        pool_recycle: Recycle connections after this many seconds
        echo: Whether to echo SQL statements (for debugging)
        
    Returns:
        Database instance
    """
    global _database_instance
    
    if _database_instance is None:
        # Get configuration from environment if not provided
        if connection_string is None:
            connection_string = get_config_value("dashboard.database.connection_string")
        
        if pool_size is None:
            pool_size = get_config_value("dashboard.database.pool_size", 10)
        
        if max_overflow is None:
            max_overflow = get_config_value("dashboard.database.max_overflow", 20)
        
        _database_instance = Database(
            connection_string=connection_string,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_recycle=pool_recycle,
            echo=echo
        )
    
    return _database_instance

def init_database() -> Database:
    """
    Initialize the database and create tables.
    
    Returns:
        Database instance
    """
    db = get_database()
    db.create_tables()
    return db

# Context manager for database sessions
@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Get a database session using a context manager.
    
    Yields:
        SQLAlchemy session object
        
    Example:
        with get_db_session() as session:
            result = session.query(User).all()
    """
    db = get_database()
    session = db.get_session()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger = get_logger()
        logger.error(f"Database error: {e}")
        raise
    finally:
        session.close()