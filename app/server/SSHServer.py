# SSHServer
# This class takes care of a valid SSH server, so attackers can connect in the first place
# Author: Lars Eissink
# github.com/Larse99

import socket
import threading
import paramiko
import time
from server.honeypotServer import honeyServer
from server.logHandler import logHandler

# Generate a SSH host key
HOST_KEY = paramiko.RSAKey.generate(2048)

# Initialize instances
log = logHandler().getLogger()

# Helper function to read a PROXY header
def read_proxy_header(client):
    # Read firsst bytes, with timeout.
    client.settimeout(1.0)
    try:
        data = client.recv(108, socket.MSG_PEEK)  # MSG_PEEK 'peeks' at the content, to see if there is a PROXY header
    except socket.timeout:
        data = b''

    if data.startswith(b"PROXY "):
        # If header starts with PROXY, read the whole PROXY header.
        header = b""
        while not header.endswith(b"\r\n"):
            chunk = client.recv(1)
            if not chunk:
                break
            header += chunk
        return header.decode()
    else:
        return None

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
            channel.send("root@SRV-WEB04:~# ")

            while True:
                command = ''
                while not command.endswith('\n'):

                    # Check if client gives a disconnect signal
                    data = channel.recv(1024)
                    if not data:
                        log.info(f"[SESSION] IP: {server.client_ip} | Client disconnected.")
                        return
                    command += data.decode('utf-8')

                command = command.strip()

                # List of available/fake commands - this is a mess. Need to do this another way in a new version
                if command in ['exit', 'logout', 'quit']:
                    channel.send("logout\n")
                    # logging.info(f"[SESSION] IP: {server.client_ip} | Session ended by user.")
                    log.info(f"[SESSION] IP: {server.client_ip} | Session ended by user.")
                    break
                elif command.startswith("ls"):
                    channel.send("total 180K\ndrwx------ 10 root root 4.0K Jun 27 14:13 .\ndrwxr-xr-x 19 root root 4.0K May  2 17:23 ..\n-rw-r--r--  1 root root   62 Feb  9 09:14 .bash_aliases\n-rw-------  1 root root  72K Jul  2 21:03 .bash_history\n-rw-r--r--  1 root root 1.7K Jun 27 14:13 .bashrc\n-rw-r--r--  1 root root 1.7K Jun  4 18:07 .bashrc.bak\ndrwxr-xr-x  5 root root 4.0K Nov 17  2024 .cache\ndrwx------  4 root root 4.0K Jan 26 20:00 .config\ndrwxr-xr-x  3 root root 4.0K Dec 15  2024 .dotnet\n-rw-r--r--  1 root root   31 Apr 12 15:30 .forward\n-rw-r--r--  1 root root  144 Nov 18  2024 .gitconfig\n-rw-------  1 root root   38 Jun 15 00:01 .lesshst\n-rw-r--r--  1 root root  161 Jul  9  2019 .profile\n-rw-------  1 root root   23 May  7 23:36 .python_history\n-rw-------  1 root root 1.0K Aug  2  2024 .rnd\ndrwx------  2 root root 4.0K Jun 27 14:14 .ssh\ndrwxr-xr-x  3 root root 4.0K Feb  5 21:28 .venv\ndrwxr-xr-x  2 root root 4.0K Dec 15  2024 .vim\n-rw-------  1 root root  22K Jun 15 00:00 .viminfo\ndrwxr-xr-x  5 root root 4.0K May 12 21:13 .vscode-server\n-rw-r--r--  1 root root  350 May 12 21:13 .wget-hsts\ndrwxr-xr-x  3 root root 4.0K May  6 21:13 Development\n")
                elif command.startswith("wget "):
                    channel.send("Resolving... done.\n")
                elif command == "whoami":
                    channel.send("root\n")
                elif command.startswith("uname"):
                    channel.send("Linux SRV-WEB04.cloud.root4all.de 4.15-generic #65-Ubuntu SMP PREEMPT_DYNAMIC Mon May 19 17:15:03 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\n")
                elif command == "pwd":
                    channel.send("/root\n")
                elif command.startswith("cd "):
                    channel.send("")
                elif command == "cat /etc/passwd":
                    channel.send("root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:User,,,:/home/user:/bin/bash\n")
                elif command.startswith("ps"):
                    channel.send("USER       PID     %CPU %MEM    VSZ   RSS      TTY     STAT   START     TIME  COMMAND\nroot       1       0.0  0.1     18500  3200    ?       Ss     10:00     0:00  /bin/bash\nroot       941     0.0  0.3     96960 13056    ?       Ss     Jun16     0:03  /usr/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -S /run/haproxy-master.sock\nroot       124525  0.0  0.0     22096  2112    ?       Ss     Jun27     0:00  nginx: master process /usr/sbin/nginx -g dae\nwww-data   124526  0.0  0.1     23656  5952    ?       S      Jun27     0:00  nginx: worker process\nwww-data   124527  0.0  0.1     23764  5952    ?       S      Jun27     0:14  nginx: worker process\nroot       749     0.0  1.0     337216 42644   ?       Ss     Jun16     2:55  php-fpm: master process (/etc/php/5.6/fpm/php-fpm.conf)\ncheckmate  879     0.0  0.7     337828 28804   ?       S      Jun16     0:20  php-fpm: pool checkmate.com-5.6\ncheckmate  885     0.0  0.7     337828 29828   ?       S      Jun16     0:20  php-fpm: pool checkmate.com-5.6\ncheckmate  886     0.0  0.7     337828 29572   ?       S      Jun16     0:19  php-fpm: pool checkmate.com-5.6\ndidyou     887     0.0  0.7     337828 29572   ?       S      Jun16     0:19  php-fpm: pool didyoureally.com-5.6\ndidyou     890     0.0  0.7     337828 28932   ?       S      Jun16     0:19  php-fpm: pool didyoureally.com-5.6\nmysql      807     1.0 22.4     1825256 441392 ?       Ssl    Jun27   115:47  /usr/sbin/mysqld\n")
                elif command in ["ifconfig", "ip a"]:
                    channel.send("eth0: inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255\n")
                elif command == "df -h":
                    channel.send("/dev/sda1        50G   10G   40G  20% /\n")
                elif command == "top":
                    channel.send("top: failed tty get\n")
                elif command == "clear":
                    channel.send("\033c")  # ANSI clear screen
                elif command == "history":
                    channel.send("1  ls\n2  whoami\n3  cat /etc/passwd\n")
                elif command.startswith("sudo "):
                    channel.send("bash: sudo: command not found\n")
                elif command.startswith(("vi", "vim", "nano")):
                    channel.send("Terminal too small\n")
                elif command.startswith("man "):
                    channel.send(f"No manual entry for {command.split()[1]}\n")
                elif command.startswith("rm -rf /"):
                    channel.send("rm: it’s going to be a bad day...\n")
                elif command.startswith("ping"):
                    channel.send("PING google.com (8.8.8.8): 56 data bytes\n64 bytes from 8.8.8.8: icmp_seq=0 ttl=57 time=10.1 ms\n")
                elif command == "curl ifconfig.me":
                    channel.send(f"{server.client_ip}\n")
                elif command == "sl":
                    channel.send("Did you mean 'ls'?\n")
                elif command == "fortune":
                    channel.send("You will debug something for hours just to realize it was a missing semicolon.\n")
                elif command == "telnet towel.blinkenlights.nl":
                    channel.send("Trying 212.71.252.29...\nConnected to towel.blinkenlights.nl.\nEscape character is '^]'.\n[Connection closed by foreign host]\n")
                elif command.startswith("which"):
                    channel.send(f"/usr/sbin/{command.split()[1]}\n")
                elif command == "mysql":
                    channel.send(f"ERROR 2002 (HY000): Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)\n")
                # Fake systemctl LOL
                elif command.startswith("systemctl"):
                    if "status" in command:
                        # Extract the service name from the command
                        parts = command.strip().split()
                        try:
                            service_name = parts[2] if len(parts) >= 3 else "unknown"
                        except IndexError:
                            service_name = "unknown"

                        channel.send(f"● {service_name}.service - The {service_name.capitalize()} Service\n")
                        channel.send(f"   Loaded: loaded (/lib/systemd/system/{service_name}.service; enabled; vendor preset: enabled)\n")
                        channel.send(f"   Active: failed (Result: exit-code) since Tue 2025-07-04 22:15:01 CEST; 1min 30s ago\n")
                        channel.send(f"  Process: 1005 ExecStart=/usr/sbin/{service_name}ctl start (code=exited, status=1/FAILURE)\n")
                    elif any(word in command for word in ["start", "stop", "restart"]):
                        channel.send("==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===\n")
                        channel.send("Authentication is required to manage system services or units.\n")
                        channel.send("Authenticating as: root\n")
                        channel.send("Password: \n")
                        time.sleep(1)
                        channel.send("Sorry, try again.\n")
                    else:
                        channel.send("System has not been booted with systemd as init system (PID 1). Can't operate.\n")
                        channel.send("Failed to connect to bus: Host is down\n")
                else:
                    channel.send(f"bash: {command}: command not found\n")

                # We only want to log if a command is entered. Otherwise the logfile will be enormous.
                if command:
                    log.info(f"[SHELL] IP: {server.client_ip} | Command: {command}")

                # Always return a prompt.
                channel.send("root@SRV-WEB04:~# ")

        except Exception as e:
            log.exception(f"[ERROR] Fake shell error for {server.client_ip}: {e}")
        finally:
            try:
                channel.close()
            except:
                pass

    def handleConnection(self, client, addr):
        # addr[0] is just the regular IP. 
        client_ip = addr[0]

        # Get IP from PROXY header
        # Basically, we will always use the regular IP. Except for if there is a PROXY header, then we will read the IP from the header.
        # This has the advantage of a automatic fallback, in case there is no PROXY header.
        proxy_header = read_proxy_header(client)
        if proxy_header:
            # If Proxy header exists, parse the whole thing
            parts = proxy_header.strip().split()
            if len(parts) >= 6:
                # This is the Client IP (third item in the list). 
                # If there is a PROXY header, we will replace client_ip with the IP from the list
                client_ip = parts[2] 
            else:
                log.warning(f"[WARN] Invalid PROXY header: {proxy_header}")

        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)

        # Pass the client IP to the honeyServer
        server = honeyServer(client_ip)

        try:
            transport.start_server(server=server)
            channel = transport.accept(20)

            if channel is not None:
                server.event.wait(10)
                if not server.event.is_set():
                    log.warning(f"[WARN] IP: {client_ip} | Client never requested a shell.")
                    return

                self.fakeShell(channel, server)

        except Exception as e:
            log.error(f"[ERROR] Transport error from {client_ip}: {e}")
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

        # For logging purposes, we log when the server started.
        log.info(f"[*] Listening for connections on {self.bindIp}:{self.bindPort}...")

        while True:
            client, addr = sock.accept()

            # Print to console if someone connects
            print(f"[+] Connection from {addr[0]}:{addr[1]}")

            # Log if someone connects
            log.info(f"[+] Connection from {addr[0]}:{addr[1]}")

            t = threading.Thread(target=self.handleConnection, args=(client, addr))
            t.start()
