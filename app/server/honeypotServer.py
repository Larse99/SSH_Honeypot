# HoneypotServer
# This class acts as a FAKE SSH server.
# Author: Lars Eissink
# Github.com/Larse99

import threading
import paramiko
import logging
from server.geoLocator import geoLocator

# Initialize instance
geo = geoLocator()

class honeyServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip

    def check_auth_password(self, username, password):
        # Get the country of IP
        country = geo.getCountryName(self.client_ip)

        logging.info(f"[AUTH] IP: {self.client_ip} | Country: {country} | Username: {username} | Password: {password}")

        # Set a user list
        userList = [
            "root", "admin", "webadmin"
        ]

        # Set a password list
        passwordList = [
            "toor", "root", "password",
            "webadmin", "admin", "webmaster",
            "maintenance"
        ]

        # Only grant access if password has been 'cracked'
        if username in userList and password in passwordList:
            logging.info(f"[AUTH] IP: {self.client_ip} | Country: {country} | Session opened!")
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
