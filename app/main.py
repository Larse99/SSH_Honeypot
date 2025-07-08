# SSH Honeypot
# Hosts a fake-SSH server on any port and logs the credentials
# Author: Lars Eissink
# github.com/Larse99

# Import needed classes
from server.honeypotServer import *
from server.SSHServer import SSHServer
from server.logHandler import logHandler

# Initialize log
log = logHandler().getLogger()

if __name__ == '__main__':
    server = SSHServer(bindPort=2222)
    server.start()