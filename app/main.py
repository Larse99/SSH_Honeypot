# SSH Honeypot
# Hosts a fake-SSH server on any port and logs the credentials
# Author: Lars Eissink
# github.com/Larse99

# Import needed classes
from server.honeypotServer import *
from server.SSHServer import SSHServer

# Initializing

# Set logging parameters
logging.getLogger("paramiko.transport").setLevel(logging.WARNING)

logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    force=True,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

if __name__ == '__main__':
    server = SSHServer(bindPort=2222)
    server.start()