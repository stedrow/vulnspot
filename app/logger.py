import logging
import sys

# Store the default level for the application
DEFAULT_LOG_LEVEL = logging.INFO

def get_logger(name: str, level: int = DEFAULT_LOG_LEVEL) -> logging.Logger:
    """Gets a logger instance.

    Configures the root logger with a stream handler and formatter
    if no handlers are already configured on the root logger.
    Sets the specified level on the requested logger instance.
    """
    # Configure root logger only if it has no handlers
    if not logging.getLogger().handlers:
        root_handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        root_handler.setFormatter(formatter)
        logging.getLogger().addHandler(root_handler)
        logging.getLogger().setLevel(DEFAULT_LOG_LEVEL) # Set root logger level

    logger = logging.getLogger(name)
    logger.setLevel(level) # Set level for the specific logger instance
    return logger

# Default application logger
# Modules can import this directly: from .logger import logger
logger = get_logger("app")
