# SSHServer
# This class takes care of a valid SSH server, so attackers can connect in the first place
# Author: Lars Eissink
# github.com/Larse99

import socket
import threading
import paramiko
import logging
from server.honeypotServer import honeyServer

# Generate a SSH host key
HOST_KEY = paramiko.RSAKey.generate(2048)

class SSHServer:
    def __init__(self, bindIp="0.0.0.0", bindPort=2222):
        self.bindIp     = bindIp
        self.bindPort   = bindPort

    def handleConnection(self, client, addr):
        client_ip = addr[0]
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)

        server = honeyServer(client_ip)  # IP meegeven!

        try:
            transport.start_server(server=server)
            channel = transport.accept(20)
            if channel is not None:
                channel.close()
        except Exception as e:
            logging.error(f"Transport error from {client_ip}: {e}")
        finally:
            transport.close()

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.bindIp, self.bindPort))
        sock.listen(100)

        print(f"[*] Listening for connections on {self.bindIp}:{self.bindPort}...")

        while True:
            client, addr = sock.accept()
            print(f"[+] Connection from {addr[0]}:{addr[1]}")
            t = threading.Thread(target=self.handleConnection, args=(client, addr))
            t.start()