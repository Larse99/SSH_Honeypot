# HoneypotServer
# This class acts as a FAKE SSH server.
# Author: Lars Eissink
# Github.com/Larse99

import threading
import paramiko
import logging

class honeyServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip

    def checkChannelRequest(self, kind):
        if kind == 'selection':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username, password):
        # logging.info(f"[AUTH] Username: {username} | Password: {password}")
        logging.info(f"[AUTH] IP: {self.client_ip} | Username: {username} | Password: {password}")
        
        # *never* accept a connection, always fail.
        return paramiko.AUTH_FAILED