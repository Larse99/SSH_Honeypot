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

    def fakeShell(self, channel, server):
        try:
            channel.send(f"""
 _____             _   _  _          _ _ 
|  __ \           | | | || |   /\   | | |
| |__) |___   ___ | |_| || |_ /  \  | | |
|  _  // _ \ / _ \| __|__   _/ /\ \ | | |
| | \ \ (_) | (_) | |_   | |/ ____ \| | |
|_|  \_\___/ \___/ \__|  |_/_/    \_\_|_|
========== Powered by Root4all ==========
                                        
System info:
Hostname····: SRV-WEB04.cloud.root4all.de
Distro······: Ubuntu 18.04.1 LTS
Kernel······: Linux 4.15
Uptime······: up 6 weeks, 2 days, 1 hour, 31 minutes
Load········: 0.18 (1m), 0.24 (5m), 0.24 (15m)
Processes···: 186 (root), 89 (user), 275 (total)
CPU·········: (4 vCPU)
Memory······: 1.1Gi used, 2.6Gi avail, 3.7Gi total

Disk usage:
/                              20% used out of  31G
[==========········································]
/webdata                       11% used out of  27G
[=====·············································]
/encrypted                     13% used out of  27G
[======············································]
""")
            channel.send("root@SRV-WEB04:~$ ")

            while True:
                command = ''
                while not command.endswith('\n'):

                    # Check if client gives a disconnect signal
                    data = channel.recv(1024)
                    if not data:
                        logging.info(f"[SESSION] IP: {server.client_ip} | Client disconnected.")
                        return
                    command += data.decode('utf-8')

                command = command.strip()

                # List of available commands
                if command in ['exit', 'logout', 'quit']:
                    channel.send("logout\n")
                    logging.info(f"[SESSION] IP: {server.client_ip} | Session ended by user.")
                    break
                elif command == "ls":
                    channel.send("Webdata my.cnf reset_password.sh\n")
                elif command.startswith("wget "):
                    channel.send("Resolving... done.\n")
                elif command == "whoami":
                    channel.send("root\n")
                elif command.startswith("uname"):
                    channel.send("Linux SRV-WEB04.cloud.root4all.de 4.15-generic #65-Ubuntu SMP PREEMPT_DYNAMIC Mon May 19 17:15:03 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux")
                else:
                    channel.send(f"bash: {command}: command not found\n")

                logging.info(f"[SHELL] IP: {server.client_ip} | Command: {command}")
                channel.send("root@SRV-WEB04:~$ ")

        except Exception as e:
            logging.error(f"[ERROR] Fake shell error for {server.client_ip}: {e}")
        finally:
            try:
                channel.close()
            except:
                pass

    def handleConnection(self, client, addr):
        client_ip = addr[0]
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)

        server = honeyServer(client_ip)

        try:
            transport.start_server(server=server)
            channel = transport.accept(20)

            if channel is not None:
                server.event.wait(10)
                if not server.event.is_set():
                    logging.warning(f"[WARN] IP: {client_ip} | Client never requested a shell.")
                    return

                self.fakeShell(channel, server)

        except Exception as e:
            logging.error(f"[ERROR] Transport error from {client_ip}: {e}")
        finally:
            try:
                transport.close()
            except:
                pass

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
