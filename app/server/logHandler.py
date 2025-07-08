# logHandler
# Handles all the logs, using Logger.
# Author: Lars Eissink
# github.com/Larse99

import logging
import os

class MaxLevelFilter(logging.Filter):
    """
    This sets a max filter for logging. We need this class within our Loghandler,
    to successfully split everything into a regular.log and a exception.log
    """
    def __init__(self, level):
        super().__init__()
        self.max_level = level

    def filter(self, record):
        return record.levelno <= self.max_level

class logHandler():
    """
    This class handles all of our logging. We needed a small custom solution,
    so we can split everything into different logfiles.
    The maxLevelFilter class is needed for splitting.
    """
    def __init__(self, logDir='logs'):
        self.logDir = logDir
        os.makedirs(self.logDir, exist_ok=True)
        self.logger = logging.getLogger('honeypot')
        self.logger.setLevel(logging.DEBUG) # For debugging purposes

        # Sometimes you can get double handlers, this will take care of it
        if not self.logger.handlers:
            self._addHandlers()

    def _addHandlers(self):
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # honeypot.log handler -> Only DEBUG and INFO
        honeypotHandler = logging.FileHandler(os.path.join(self.logDir, 'honeypot.log'))
        honeypotHandler.setLevel(logging.DEBUG)
        honeypotHandler.addFilter(MaxLevelFilter(logging.INFO))
        honeypotHandler.setFormatter(formatter)
        self.logger.addHandler(honeypotHandler)

        # exception.log handler -> ERROR and higher
        exceptionHandler = logging.FileHandler(os.path.join(self.logDir, 'exception.log'))
        exceptionHandler.setLevel(logging.ERROR)
        exceptionHandler.setFormatter(formatter)
        self.logger.addHandler(exceptionHandler)
    
    def getLogger(self):
        return self.logger