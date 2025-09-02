####################################################################################################
#
#  extra Python modules to be installed, if not already
#
#    pip install "netifaces>=0.11.0"
#    pip install "pyyaml>=6.0.2"
#    pip install "dnspython>=2.7.0"
#    pip install "requests>=2.32.3"
#    pip install "scapy>=2.6.1"
#    pip install "zeroconf>=0.147.0"
#
####################################################################################################
#
#  install https://npcap.com/#download
#
####################################################################################################
#
#  want to make it an executable for Windows?
#
#    pyinstaller --onefile "Scan-Network.py" --exclude-module pkg_resources
#
####################################################################################################

####################################################################################################
### Imports
####################################################################################################
# base imports
import os
import platform
import sys
import getopt
import smtplib
import ssl
import socket
import struct
import time
import ipaddress
import select
import re
import subprocess
# import json
import threading

from datetime             import datetime
from email.mime.base      import MIMEBase
from email.mime.text      import MIMEText
from email.mime.multipart import MIMEMultipart
from email                import encoders
from queue                import Queue
from dataclasses          import dataclass
from typing               import List, Dict
from collections          import defaultdict


# third party imports
import yaml
# import dns.resolver
import psutil
import netifaces

# from requests             import get
from scapy.all            import *
from zeroconf             import (
                                 IPVersion,
                                 ServiceBrowser,
                                 ServiceStateChange,
                                 Zeroconf
)

#---------------------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------------------
####################################################################################################
### Dataclasses
####################################################################################################
@dataclass
class Device:
    ip:   str
    host: str
    port: int
    props:   List[str]
    weight: int
    priority: int
    text: bytes

@dataclass
class Service:
    name:    str
    devices: List[Device]
#---------------------------------------------------------------------------------------------------

####################################################################################################
### Global variablesDataclasses
####################################################################################################

#---------------------------------------------------------------------------------------------------
# general
VERSION         = "4.00"
DEBUG           = False

COMPUTERNAME    = os.getenv('COMPUTERNAME')

strScriptName   = os.path.basename(sys.argv[0])
strScriptPath   = os.path.dirname(os.path.realpath(sys.argv[0]))
strScriptBase   = os.path.splitext(strScriptName)[0]
YAMLfile        = os.path.join(strScriptPath, strScriptBase + '.yaml')

SPACES          = " " * 120
BOOLEAN_MAP     = {True: "Yes", False: "No"}

#---------------------------------------------------------------------------------------------------
# reporting related
screen_enabled  = False
logfile_enabled = False
LOGfile         = ""

#---------------------------------------------------------------------------------------------------
# Ping related
ping_count      =   3
ping_length     = 256
ping_timeout    = 300
ScanDict        = {}
ScanList        = ""
NETfile         = ""
TXTfile         = ""
ScanHost_cntr   = 0

#---------------------------------------------------------------------------------------------------
# ARP related
arpscan_enabled    = True
arp_timeout        = 1
arpalive           = []
# list of dictionaries of IP and mac address of devices responding to arp requests Eg:
"""
[
  ...
  {'ip': '192.168.001.004', 'mac: 'd8:44:89:27:a7:ee'},
  {'ip': '192.168.001.005', 'mac: 'ac:84:c6:1a:6b:74'},
  {'ip': '192.168.001.006', 'mac: 'ac:84:c6:27:ee:2a'},
  ...
]
"""

#---------------------------------------------------------------------------------------------------
# IP related
netscan_enabled    = True
listscan_enabled   = True
IP_NET             = ""
IP_MASK            = ""
IP_START           = ""
IP_END             = ""
host_ip            = ""                  # ip address of host running this script
host_mac           = ""                  # mac address of host running this script
host_net           = False               # host runnin this script in the network to scan?
ipalive            = []                  # list of dictionaries containing ip, host, mac and ports
"""
[
  {'ip': '192.168.001.001', 'hostname': '', 'mac': '', 'ports': [9, 22, 53, 80, 139, 515, 8000]},
  {'ip': '192.168.001.002', 'hostname': '', 'mac': '', 'ports': []},
  {'ip': '192.168.001.003', 'hostname': '', 'mac': '', 'ports': []},
  {'ip': '192.168.001.004', 'hostname': '', 'mac': '', 'ports': [80, 443]},
  ...
]
"""
ipal               = []                  # simple list of ip addresses alive
ipna               = []                  # simple list of ip addresses not alive

#---------------------------------------------------------------------------------------------------
# Port scan related
port_advisory        = True
port_timeout         =    2              # Socket timeout in seconds
port_threads         =  []
portthread_count     =   20              # Number of threads to use for scanning

netportscan_enabled  = False
netportdesc_enabled  = False             # add desciption
netport_start        =    1
netport_end          = 1024
netports_open        = []                # list of open ports for specific IP during a full net scan
"""
[21, 80, 443]
"""
listportscan_enabled = False
listportdesc_enabled = False
listportscan_info    = False
listport_start       =    1
listport_end         = 1024
list_count           =    0
list_cntr            =    0

port_queue           = Queue()           # queue to hold the ports to be scanned
thread_lock          = threading.Lock()  # Thread-safe lock for printing/adding to open_ports list
PortsDict            = {}                # dictionary with ports listed in YAML file
"""
{ ... 146: 'ISO-IP0', 147: 'ISO-IP', '148': 'Jargon', ....}
"""
ports_open           = []                # list of ports open found during a port scan
"""
[21, 80, 443]
"""
ports_list           = []                # list of ports listed in Scanlist Eg: [0, 21, 8009]
ports_mdns           = {}                # dictionary which will list mdns ports for a n ip address
"""
[
  ...
  "192.168.001.061": [8009],
  "192.168.001.017": [0, 21],
  "192.168.001.050": [0],
  ...
}
"""

#---------------------------------------------------------------------------------------------------
#mDNS scan related
mDNSscan_enabled = False
mDNS_timeout     = 180
mDNS_timeend     =   0
mDNSfile         = ""
mDNS_listed      = {}                    # dictionary of dictionaries of listed services
"""
{
  ...
  '_afpovertcp._tcp.local.': Service(
                                      name='AFPOVERTCP',
                                      devices=[]
                                    ),
  '_googlecast._tcp.local.': Service(
                                      name='CHROMECAST',
                                      devices=[
                                                Device(
                                                        ip='192.168.001.061',
                                                        host='ChromeCast-Bedroom.home',
                                                        port=8009,
                                                        props=[
                                                                'path: /',
                                                                'version: 1.11.2',
                                                                'api: 0.1',
                                                                'id: edc78a56-'
                                                              ],
                                                        weight=0,
                                                        priority=0,
                                                        text="some text"
                                                      )
                                              ]
                                    ),
  '_device-info._tcp.local.': Service(
                                       name='DEVICE INFO',
                                       devices=[
                                                 Device(
                                                         ip='192.168.001.017',
                                                         host='storage2.home',
                                                         port=0,
                                                         props=[]
                                                         weight=0,
                                                         priority=0,
                                                         text="some text"
                                                        ),
                                                 Device(
                                                         ip='192.168.001.049',
                                                         host='volumio-living.home',
                                                         port=0,
                                                         props=[],
                                                         weight=0,
                                                         priority=0,
                                                         text="some text"
                                                        )
                                               ]
                                      ),
  ....
}
"""
mDNS_unlisted    = {}                    # dictionary of dictionaries of unlisted mDNS services
"""
same format az mDNS_listed
"""
mDNS_count       = 0
mDNS_cntr        = 0

#---------------------------------------------------------------------------------------------------
# SMTP related
smtp_enabled    = False
smtpserver      = "smtpserver"
smtpport        = 587
smtptls         = True
smtpCA          = False
smtplogin       = ""
smtppass        = ""
From            = ""
To              = ""

#---------------------------------------------------------------------------------------------------
#syslog related
syslog_enabled   = False
syslogserver     = ""
syslogport       = 0
FACILITY = {
    'kern':    0, 'user':    1, 'mail':      2, 'daemon':  3,
    'auth':    4, 'syslog':  5, 'lpr':       6, 'news':    7,
    'uucp':    8, 'cron':    9, 'authpriv': 10, 'ftp':    11,
    'local0': 16, 'local1': 17, 'local2':   18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6':   22, 'local7': 23,
}

LEVEL = {
    'emerg':   0, 'alert':  1, 'crit': 2, 'err':   3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

#---------------------------------------------------------------------------------------------------
# Create a secure SSL context
sslcontext = ssl.create_default_context()
if smtptls:
    try:
        ssl._create_unverified_https_context = ssl._create_unverified_context

    except AttributeError:
        # Legacy Python that doesn't verify HTTPS certificates by default
        pass

####################################################################################################
### Classes
####################################################################################################
#---------------------------------------------------------------------------------------------------
# Class for ping
#---------------------------------------------------------------------------------------------------
ICMP_ECHO_REQUEST =   8

class Pinger():
    """ Pings to a host -- the Pythonic way"""

    def __init__(self, target_host, count=5, size=65, timeout=300, debug=False):
        self.target_host = target_host
        self.count = count
        self.timeout = timeout / 1000  # convert to seconds - select uses seconds
        self.size = size
        self.debug = debug

    def do_checksum(self, source_string):
        """Verify the packet integrity"""
        if not isinstance(source_string, (bytes, str)):
            raise TypeError("source_string must be bytes or str")

        if not source_string:
            return 0

        pchecksum = 0
        max_count = (len(source_string) // 2) * 2
        count = 0

        while count < max_count:
            val = source_string[count + 1] * 256 + source_string[count]
            pchecksum += val
            pchecksum &= 0xffffffff
            count += 2

        if max_count < len(source_string):
            last_byte = source_string[-1]
            pchecksum += last_byte if isinstance(source_string, bytes) else ord(last_byte)
            pchecksum &= 0xffffffff

        pchecksum = (pchecksum >> 16) + (pchecksum & 0xffff)
        pchecksum += (pchecksum >> 16)
        answer = ~pchecksum & 0xffff
        answer = (answer >> 8) | ((answer << 8) & 0xff00)
        return answer

    def receive_pong(self, sock, ID, timeout):
        """
        Receive ping from the socket.
        """
        time_remaining = timeout
        while True:
            start_time = time.time()
            readable = select.select([sock], [], [], time_remaining)
            time_spent = time.time() - start_time
            if readable[0] == []: # Timeout
                return

            time_received = time.time()
            recv_packet, addr = sock.recvfrom(1024)
            icmp_header = recv_packet[20:28]
            ptype, pcode, pchecksum, packet_ID, sequence = struct.unpack("bbHHh", icmp_header)
            if packet_ID == ID:
                bytes_In_double = struct.calcsize("d")
                time_sent = struct.unpack("d", recv_packet[28:28 + bytes_In_double])[0]
                return time_received - time_sent

            time_remaining = time_remaining - time_spent
            if time_remaining <= 0:
                return

    def send_ping(self, sock,  ID):
        """
        Send ping to the target host
        """
        target_addr  =  socket.gethostbyname(self.target_host)

        my_checksum = 0

        # Create a dummy heder with a 0 checksum.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
        bytes_In_double = struct.calcsize("d")
        data = (192 - bytes_In_double) * "Q"
        data = struct.pack("d", time.time()) + bytes(data.encode('utf-8'))

        # Get the checksum on the data and the dummy header.
        my_checksum = self.do_checksum(header + data)
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1)
        ppacket = header + data
        sock.sendto(ppacket, (target_addr, 1))

    def ping_once(self):
        """
        Returns the delay (in seconds) or none on timeout.
        """
        icmp = socket.getprotobyname("icmp")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except OSError as se:
            if se.errno == 1:
                raise PermissionError("ICMP messages can only be sent from root user processes.") from se
            raise
        except Exception as ee:
            if self.debug:
                print(f"Unexpected exception: {ee}")
            raise

        my_ID = os.getpid() & 0xFFFF

        self.send_ping(sock, my_ID)
        delay = self.receive_pong(sock, my_ID, self.timeout)
        sock.close()
        return delay

    def ping(self):
        """
        Run the ping process
        """

        tmax=0
        tmin=0
        lost=0
        ttot=0

        for _ in range(self.count):
            try:
                delay  =  self.ping_once()
            except socket.gaierror as se:
                if self.debug:
                    print(f"Ping failed. (socket error: {se[1]})")
                    break

            if delay is None:
                # print("Ping failed. (timeout within %ssec.)" % self.timeout)
                if self.debug:
                    print("Request timed out.")
                delay = int(self.timeout * 1000)
                lost = lost+1

            else:
                delay = int(delay * 1000)
                if self.debug:
                    print(f"Reply from {self.target_host}",end = '')
                    print(f" time={delay:0.0f}ms")

            tmax = max(tmax, delay)
            tmin = min(tmin, delay)
            ttot = ttot + delay

        # convert lost to %
        lost = int((lost/self.count)*100)
        # calc average time
        tavg = int(ttot/self.count)
        return tmin, tmax, tavg, lost
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
# Class for mDNS listener
#---------------------------------------------------------------------------------------------------
class MyListener:
    def __init__(self, zeroconf_instance, listed_services=None):
        self.zeroconf = zeroconf_instance
        self.all_services = listed_services
        self.unlisted_services: Dict[str, Service] = {}
        self.known_services = {key: value.name for key, value in listed_services.items()}

    def add_service(self, _zeroconf, stype, name):
        # normalize type
        norm_type = stype.lower()
        if not norm_type.endswith('.'):
            norm_type += '.'

        # Special case: discover service types
        if stype == "_services._dns-sd._udp.local.":
            ServiceBrowser(self.zeroconf, name, self)
            return

        info = self.zeroconf.get_service_info(stype, name)
        if not info:
            return

        ip_address = socket.inet_ntoa(info.addresses[0]) if info.addresses else 'N/A'
        host_name  = info.server if info.server else 'N/A'
        port       = info.port
        props      = [
            f"{key.decode('utf-8')}: {value.decode('utf-8') if value else ''}"
            for key, value in info.properties.items()
            if key and value
        ]

        weight = info.weight if info.weight else 0
        prio   = info.priority if info.priority else 0
        tmp = info.text.decode('utf-8', errors='replace') if info.text else ''
        txt = re.sub(r'[^\x20-\x7E]', ' ', tmp)

        device = Device(
            ip       = reformat_ip(ip_address, True),
            host     = host_name.split('.')[0].lower(),
            port     = port,
            props    = props,
            weight   = weight,
            priority = prio,
            text     = txt
        )

        # Add to all_services
        if norm_type not in self.all_services:
            self.all_services[norm_type] = Service(name=norm_type.upper(), devices=[])
        self.all_services[norm_type].devices.append(device)

        # Add to unlisted_services if not in known_services
        if norm_type not in self.known_services:
            if norm_type not in self.unlisted_services:
                self.unlisted_services[norm_type] = Service(name=norm_type.upper(), devices=[])
            self.unlisted_services[norm_type].devices.append(device)

     # needed methode but not used
    def remove_service(self, _zeroconf, stype, name):
        pass

     # needed methode but not used
    def update_service(self, _zeroconf, stype, name):
        pass
#---------------------------------------------------------------------------------------------------


####################################################################################################
### Functions - callback
####################################################################################################

#---------------------------------------------------------------------------------------------------
def port_threadworker(ip, port):

    """
    Callback function for the port threads
    It gets a port from the queue and calls the scan_port function
    """

    while not port_queue.empty():
        port = port_queue.get()
        scan_port(ip, port, True)
        port_queue.task_done()
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def mdns_on_service_state_change(_zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange):

    """
    Callback function for the mDNS browser
    It gets the information from the mDNS service being published
    """
    ip   = ""
    host = ""
    port = ""

    if state_change is ServiceStateChange.Added:

        # device = name.replace(service_type, "")[:-1]
        info   = _zeroconf.get_service_info(service_type, name)

        if info:
            # only get first IP address
            for ip in info.parsed_scoped_addresses():
                break

            # check if IP address is IPV4
            if is_ipv4(ip):
                try:
                    socket.inet_aton(ip)
                    try:
                        host, _, _ = socket.gethostbyaddr(ip)
                    except:
                        host = "<not in DNS>"
                except socket.error:
                    ip = "               "
            else:
                ip = f"<{ip[0:14]}>"

            ip_15 = reformat_ip(ip, True)

            port = info.port

            props = []
            if info.properties:
                for key, value in info.properties.items():
                    strkey = key.decode("utf-8")
                    if strkey != "" and 'board' not in strkey:
                        if value is not None:
                            strvalue = value.decode("utf-8")
                        else:
                            strvalue = "None"
                        line = f"{strkey}: {strvalue}"
                        if line not in props:
                            props.append(line)

            weight = info.weight if info.weight else 0
            prio   = info.priority if info.priority else 0
            tmp = info.text.decode('utf-8', errors='replace') if info.text else ''
            txt = re.sub(r'[^\x20-\x7E]', ' ', tmp)

            new_device = Device(ip_15, host, port, props, weight, prio, txt)
            mDNS_listed[service_type].devices.append(new_device)
#---------------------------------------------------------------------------------------------------


####################################################################################################
### Functions
####################################################################################################
#---------------------------------------------------------------------------------------------------
def getargs(argv):

    """
    Function to get and test command line arguments
    """

    global YAMLfile, DEBUG
    global ScanList, IP_NET, IP_MASK
    global NETfile

    try:
        opts, args = getopt.getopt(argv,"DY:P:N:M:")

    except getopt.GetoptError:
        print(strScriptBase + " host [-D] [ -Y YAML-filename ] [ -P ScanList-filename ] -N net_to_scan [-M mask ]")
        sys.exit(1)

    for opt, arg in opts:
        if opt == '-D':
            DEBUG = True
        elif opt in ("-Y"):
            YAMLfile = arg
            YAMLfile = os.path.join(strScriptPath, YAMLfile)
            if os.path.exists(YAMLfile):
                pass
            else:
                print(f"Error: {YAMLfile} not found")
                sys.exit(2)
        elif opt in ("-P"):
            ScanList = arg
            ScanList = os.path.join(strScriptPath, ScanList)
            if os.path.exists(ScanList):
                loadScanDict()
            else:
                print(f"Error: {ScanList} not found")
                sys.exit(2)
        elif opt in ("-N"):
            IP_NET = arg
            NETfile = os.path.join(strScriptPath, strScriptBase + f"_{IP_NET}.net")
        elif opt in ("-M"):
            IP_MASK = arg

    if IP_NET == "":
        print("Error: -N <net_to_scan> is a mandatory option.")
        print("Eg: -N 192.168.1")
        sys.exit(3)

    if IP_MASK == "":
        IP_MASK = "255.255.255.0"
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def loadScanDict():

    """
    Function to load all line entries from a list to scan into a dictionary
    IP address gets formatted in 111.111.111.111 format
    """

    with open(ScanList, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if len(line) > 0:
                if line[0] != '#':
                    if line.count(";") != -1:
                        parts = line.split(";")
                        hostname = parts[0].strip()
                        ip       = parts[1].strip()
                        ip_15    = reformat_ip(ip, True)
                        ScanDict[ip_15] = hostname
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def port_scanning_advisory():
    advisory = """
  ################################################################################

  This application includes port scanning that can help you diagnose
  your network for issues, discover services, and improve security.
  However, this comes with responsibility.

  Before you scan for ports, please keep these best practices in mind:

  Scan Only What You Own or Have Permission:
  Always ensure you have explicit authorization before scanning any network.
  Unauthorized scans can be seen as hostile activity and may violate laws.

  Respect Network Stability:
  Aggressive or frequent scans can overload systems or trigger alarms.
  Use scanning features thoughtfully.
  Avoid scanning production environments without proper planning.

  Stay Compliant:
  Port scanning may be restricted by local regulations or organizational terms.
  Make sure your usage aligns with all applicable rules.

  Be Transparent:
  If you're scanning within a shared or corporate environment
  notify relevant stakeholders.
  Transparency builds trust and avoids unnecessary confusion or concern.

  Use It as a Tool, Not a Weapon:
  Port scanning is a valuable diagnostic and security resource
  but misuse can lead to serious consequences.
  Use it to strengthen systems, not probe them without cause.

 ################################################################################
"""
    print(advisory)
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def is_service_running(service_name):

    """
    Function to check is a service is running
    OS sensitive
    """

    os_type = platform.system().lower()

    ret = False

    try:
        if os_type == "windows":
            result = subprocess.run(["sc", "query", service_name], capture_output=True, text=True, check=True)
            if "RUNNING" in result.stdout:
                ret = True

        if os_type == "linux":
            result = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True, check=True)
            if "active" in result.stdout:
                ret = True

        if os_type == "darwin":  # macOS
            result = subprocess.run(["launchctl", "list"], capture_output=True, text=True, check=True)
            if service_name in result.stdout:
                ret = True

        return ret

    except:
        return ret
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def flush_ipcache():

    """
    Function to flush IP cache
    OS sesnsitive
    """

    os_type = platform.system().lower()

    try:
        if os_type == "windows":
            subprocess.run(["ipconfig", "/flushdns >nul"], shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        elif os_type == "linux":
            # Try systemd-resolved first
            result = subprocess.run(["systemctl", "is-active", "systemd-resolved"], capture_output=True, text=True, check=False)
            if "active" in result.stdout:
                subprocess.run(["sudo", "systemd-resolve", "--flush-caches"], check=True)
            else:
                # Fallback to dnsmasq
                subprocess.run(["sudo", "service", "dnsmasq", "restart"], check=True)

        elif os_type == "darwin":  # macOS
            subprocess.run(["sudo", "killall", "-HUP", "mDNSResponder"], check=True)

        else:
            print(f"Unsupported OS: {os_type}")
            sys.exit(4)

    except subprocess.CalledProcessError:
        pass
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def get_mac_address_and_hostname(ip_address):

    """
    Function to get Hostname and MAC address from a IP address
    Windows only
    """

    mac_address = None
    hostname    = None

    if platform.system().lower() == "windows":
        cmd = "arp -a"
    else:
        cmd = "arp"

    try:
        with subprocess.Popen([cmd, ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            stdout, stderr = process.communicate()
            output = stdout.decode()
            lines = output.splitlines()
            for line in lines:
                if ip_address in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        # Windows uses hyphens, convert to colons
                        mac_address = parts[1].replace("-", ":")
                        break

        try:
            hostname = socket.gethostbyaddr(ip_address)[0]

        except socket.herror:
            hostname = None

    except:
        return None, None

    return mac_address, hostname
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def sendmail(From, To, Subject, Body, Attach = ""):

    """
    General function to send mails
    Windows only
    """

    msg            = MIMEMultipart()
    msg['From']    = From
    msg['To']      = To
    msg['Subject'] = Subject

    msg.attach(MIMEText(Body, 'plain'))

    if Attach != "":
        with open(Attach, "rb", encoding="utf-8") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f"attachment; filename= {Attach}")
            msg.attach(part)


    server = smtplib.SMTP(smtpserver, smtpport)
    try:

        if smtptls and not smtpCA:
            server.starttls()           # Secure the connection
        elif smtptls and smtpCA:
            server.starttls(sslcontext) # Secure the connection

        if smtplogin is not None:
            if smtplogin != "":
                server.login(smtplogin, smtppass)
        text = msg.as_string()
        server.sendmail(From, To, text)

    except:
        pass

    finally:
        server.quit()
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def syslog(message, level=LEVEL['notice'], facility=FACILITY['user'], host='localhost', port=514, proto=0, hostname = "myhost", appname = "myapp"):

    """
    Send syslog UDP packet to given host and port.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dt = datetime.now()
    if proto == 0:
        dts = dt.strftime("%b %d %H:%M:%S")
        data = f"<{level + facility*8}>{dts} {hostname} {appname}: {message}"
    else:
        dts = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        version = 1
        data = f"<{level + facility*8}>{version} {dts} {hostname} {appname} - - - \xEF\xBB\xBF{message}"
    sock.sendto(str.encode(data), (host, port))
    sock.close()
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def print_services(services: Dict[str, Service]):
    """
    helper to print mDNS dictionaries in a readable format
    """

    for service_type, service in list(services.items()):
        print(f"\nService Type: {service_type}")
        print(f"   Friendly Name: {service.name}")
        print(f"   Devices ({len(service.devices)}):")
        for device in service.devices:
            print(f"     IP: {device.ip}")
            print(f"     Host: {device.host}")
            print(f"     Port: {device.port}")
            if device.props:
                print("     Properties:")
                for prop in device.props:
                    print(f"       - {prop}")
            else:
                print("     Properties: None")
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def services_count(service_dict):
    """
    Counts the number of services that have at least one device with an IP address,
    and the number of unique IP addresses across all services.
    """

    unique_ips = set()
    services_with_ips = 0

    for service in service_dict.values():
        service_has_ip = False
        for device in service.devices:
            if device.ip:
                unique_ips.add(device.ip)
                service_has_ip = True
        if service_has_ip:
            services_with_ips += 1

    return services_with_ips, len(unique_ips)
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def ignore_extra(props, extra):
    # Extract the text portion
    try:
        text_part = extra.split("text:")[1].strip()
    except IndexError:
        return True

    # Check each key-value pair
    for item in props:
        if ':' not in item:
            # skip malformed entries
            continue

        key, value = item.split(':', 1)
        key = key.strip()
        value = value.strip()
        if f"{key}={value}" in text_part:
            return True

    # Check weight and priority
    if "weight:  0" in extra and "priority:  0" in extra:
        return True

    return False
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def is_empty_extra(extra):
    pattern = r"<weight:\s*0\s*-\s*priority:\s*0\s*-\s*text:\s*>"
    return re.fullmatch(pattern, extra.strip()) is not None
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def is_ipv4(ip):
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)

    except ValueError:
        return False
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def is_private_ip(ip):

    """
    Function to check if an IP address is in a private range
    """

    try:
        ip_tmp = ipaddress.ip_address(ip)
        return ip_tmp.is_private

    except ValueError:
        return None
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def is_private_network(network):

    """
    Function to check if an network address is in a private range
    """

    try:
        net = ipaddress.ip_network(network, strict=False)
        return net.is_private

    except ValueError:
        return None
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def extend_ip(partial_ip, netmask):

    """
    Function to extend a partial IP address to a full, based on a netmask
    """

    # Split and pad the IP to 4 octets
    octets = partial_ip.split('.')
    while len(octets) < 3:
        octets.append('0')  # You can use '1' or another default if preferred
    octets.append('1')
    full_ip = '.'.join(octets)

    # Create the network
    network = ipaddress.IPv4Network(f"{full_ip}/{netmask}", strict=False)
    return network
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def reformat_ip(ip, To15):

    """
    Function to convert an IP address to 999.999.999.999 format and back
    """

    ip_split = ip.split(".")

    if To15:
        if is_ipv4(ip):
            # Format IP parts with 3 digits, padded with zeros
            ip_split[0] = f"{int(ip_split[0]):3d}"
            ip_split[1] = f"{int(ip_split[1]):03d}"
            ip_split[2] = f"{int(ip_split[2]):03d}"
            ip_split[3] = f"{int(ip_split[3]):03d}"
            ip_15 = ".".join(ip_split)
            return ip_15
        return ip

    # Format ip addres with 3 digits to regulare one
    ip_split[0] = str(int(ip_split[0]))
    ip_split[1] = str(int(ip_split[1]))
    ip_split[2] = str(int(ip_split[2]))
    ip_split[3] = str(int(ip_split[3]))
    ip_15 = ".".join(ip_split)
    if is_ipv4(ip_15):
        return ip_15
    return ip
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def ip_to_tuple(ip):

    """
    Helper function to convert IP string to tuple of integers
    """

    return tuple(int(part) for part in ip.split('.'))
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def doping(host, ip, count, size, timeout, DEBUG):

    """
    Function to execute a ping
    """
    global ipalive

    tmin     = timeout
    tmax     = timeout
    tavg     = timeout
    lost     = 100
    DNS_host = ""
    DNS_ip   = ""
    ip_15    = reformat_ip(ip, True)

    if IP_NET in ip:
        try:
            DNS_host, _, DNS_ips = socket.gethostbyaddr(ip)
            DNS_host = DNS_host.split('.')[0].lower()
            if ip in DNS_ips:
                DNS_ip = ip
            else:
                DNS_ip = DNS_ips[0]
        except:
            DNS_host = "<not in DNS>"
            DNS_ip   = "<not in DNS>"
    else:
        try:
            DNS_ip = socket.gethostbyname(host)
        except:
            DNS_ip = ""

    if DEBUG:
        print(f"\nHost: {Host} - host: {host} - DNS_host: {DNS_host} - IP: {ip} - DNS_ip: {DNS_ip}")

    if IP_NET in ip and host_net:
        if host != DNS_host:
            msg = f"      ERROR: {host} not the same as DNS {DNS_host}"
            if syslog_enabled:
                syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)
            if smtp_enabled:
                sendmail(From, To,  msg, "")
            if screen_enabled:
                print(f"\r\n\n{msg}\n")
            if logfile_enabled:
                with open(LOGfile , 'a', encoding="utf-8") as f:
                    f.write(f"\r\n\n{msg}\n")

        if DNS_ip in ip:
            pass
        else:
            msg = f"      ERROR: {ip} not the same as DNS {DNS_ip}"
            if syslog_enabled:
                syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)
            if smtp_enabled:
                sendmail(From, To,  msg, "")
            if screen_enabled:
                print(f"\r\n\n{msg}\n")
            if logfile_enabled:
                with open(LOGfile , 'a', encoding="utf-8") as f:
                    f.write(f"\r\n\n{msg}\n")
    try:
        if ip == '':
            ip = socket.gethostbyname(host)

        # remove from ipalive
        # doing so we will end up with a list of IPs that are alive not not listed
        ip_15 = reformat_ip(ip, True)
        # do it on a copy
        for ipdict in ipalive[:]:
            if ipdict.get('ip') == ip_15:
                #remove from original
                ipalive.remove(ipdict)
                break

        pinger = Pinger(target_host=ip, count=count, size=size, timeout=timeout, debug=DEBUG)
        tmin, tmax, tavg, lost = pinger.ping()

    except Exception as e:
        print(f"here - {e}")
        if DEBUG:
            print(f"{host} not resolvable")

    if DEBUG:
        print(tmin, tmax, tavg, lost)

    return tmin, tmax, tavg, lost, ip
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def ScanHost(Host):

    """
    Function to scan a host/ip for a ping and ports
    """

    global ports_open, ports_list
    global ScanHost_cntr

    host = ""
    ip   = ""
    acti = "A"
    ports_list = []
    parts      = {}

    if ";" in Host:
        parts = Host.split(";")
        host  = parts[0].strip().split('.')[0].lower() if parts[0].strip() else ""
        ip    = parts[1].strip()
        acti  = parts[2].strip()
        ports_list = ([int(p.strip()) for p in parts[3].replace("Ports:", "").strip().split(',') if p.strip()]
                      if len(parts) > 3 and parts[3].strip() else [])

    else:
        if is_ipv4(Host):
            ip = Host
            host = ""
            acti = "A"
            ports_list = []
            try:
                host = socket.gethostbyaddr(ip)[0].lower()
            except socket.herror:
                host = ""
        else:
            host = Host
            ip   = socket.gethostbyname(host)
            acti = "A"
            ports_list = []

    print(f"\r{SPACES}\r", end="", flush=True)
    print(f"    Host: {host.upper()} - {ip}", end="", flush=True)

    tmin, tmax, tavg, lost, ip = doping(host, ip, ping_count, ping_length, ping_timeout, DEBUG)
    # print(f"\nPing IP: {ip} -> tmin: {tmin} tmax: {tmax} tavg: {tavg} lost: {lost}")

    body = f"Host : {Host}\nhost : {host}\nip   : {ip}\nacti :{acti}\nports:{ports_list}\ntmin : {tmin}\ntmax : {tmax}\ntavg : {tavg}\nlost : {lost}"

    # if no response at all but no timeout and supposed to be active
    if   lost == 100 and tmin != ping_timeout and acti == "A":
        ScanHost_cntr += 1
        msg = f"ERROR: {host.upper()} ({ip}) reachability - FAILED"
        if syslog_enabled:
            syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)
        if smtp_enabled:
            sendmail(From, To, msg, body)
        if screen_enabled:
            print(f"\r\n      {msg}\n        {body}\n")
        if logfile_enabled:
            with open(LOGfile , 'a', encoding="utf-8") as f:
                f.write(f"\r\n\n{msg}\n  {body}\n")

    # if no response at all and timeout and supposed to be active
    elif lost == 100 and tmin == ping_timeout and acti == "A":
        ScanHost_cntr += 1
        msg = f"ERROR: {host.upper()} can't be resolved to IP address - FAILED"
        if syslog_enabled:
            syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)
        if smtp_enabled:
            sendmail(From, To, msg, body)
        if screen_enabled:
            print(f"\r\n      {msg}\n        {body}\n")
        if logfile_enabled:
            with open(LOGfile , 'a', encoding="utf-8") as f:
                f.write(f"\r\n\n{msg}\n  {body}\n")

    # if got at least 1 ping back
    elif lost == ping_count - 1:
        ScanHost_cntr += 1
        msg = f"ERROR: {host.upper()} ({ip}) was slow (lost = {lost}% )"
        if syslog_enabled:
            syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)
        if smtp_enabled:
            sendmail(From, To, msg, body)
        if screen_enabled:
            print(f"\r\n      {msg}\n        {body}\n")
        if logfile_enabled:
            with open(LOGfile , 'a', encoding="utf-8") as f:
                f.write(f"\r\n\n{msg}\n  {body}\n")

    # if we got quite some pings back
    elif lost != 100:
        # check if ports listed are open
        ip_15 = reformat_ip(ip, True)
        ports_open    = []
        portsmdns     = []
        ports_notopen = []

        # get open mdns ports for a specific IP address
        if ports_mdns:
            portsmdns = ports_mdns.get(ip_15, [])

        # check if listed prots are open
        for port in ports_list:
            # skip if ports were already seen during mDNS scan
            if portsmdns and port in portsmdns:
                continue
            # check if open
            if not scan_port(ip, port, False):
                ScanHost_cntr += 1
                msg =  f"Port {port} on {host.upper()} ({ip}) is NOT open"
                # keep tracks of not-open port found
                ports_notopen.append(port)
                if screen_enabled:
                    print(f"\r\n      {msg}\n")
                if logfile_enabled:
                    with open(LOGfile , 'a', encoding="utf-8") as f:
                        f.write(f"\r\n\n{msg}\n")
                if smtp_enabled:
                    sendmail(From, To, msg, "")
                if syslog_enabled:
                    syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

        # only do a full port scan if enabled and ip address is a private address
        if listportscan_enabled and is_private_ip(ip):
            # check if there are no other ports open
            ports_open = []
            scan_ip_ports(ip, listport_start, listport_end)

            # check if listed ports are open
            for port in ports_list:
                if port in ports_open:
                    continue
                # skip if ports were already seen during mDNS scan
                if portsmdns and port in portsmdns:
                    continue
                if ports_notopen and port not in ports_notopen:
                    ScanHost_cntr += 1
                    if listportdesc_enabled:
                        desc = PortsDict.get(port, "Dynamic/Private")
                        msg =  f"Port {port} ({desc}) listed on {host.upper()} ({ip}) is NOT open"
                    else:
                        msg =  f"Port {port} listed on {host.upper()} ({ip}) is NOT open"
                    if screen_enabled:
                        print(f"\r\n      {msg}\n")
                    if logfile_enabled:
                        with open(LOGfile , 'a', encoding="utf-8") as f:
                            f.write(f"\r\n\n{msg}\n")
                    if smtp_enabled:
                        sendmail(From, To, msg, "")
                    if syslog_enabled:
                        syslog(message="    " + msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

            # check if open ports are listed
            for port in ports_open:
                if port  in ports_list:
                    continue
                ScanHost_cntr += 1
                if portsmdns and port in portsmdns:
                    if listportdesc_enabled:
                        desc = PortsDict.get(port, "Dynamic/Private")
                        msg =  f"Port {port} ({desc}) on {host.upper()} ({ip}) is open but not listed (found through mDNS)"
                    else:
                        msg =  f"Port {port} on {host.upper()} ({ip}) is open but not listed (found through mDNS)"
                else:
                    if listportdesc_enabled:
                        if port in PortsDict:
                            desc = PortsDict[port]
                        else:
                            desc = "Dynamic/Private"
                        msg =  f"Port {port} ({desc}) on {host.upper()} ({ip}) is open but not listed"
                    else:
                        msg =  f"Port {port} on {host.upper()} ({ip}) is open but not listed"
                if screen_enabled:
                    print(f"\r\n      {msg}\n")
                if logfile_enabled:
                    with open(LOGfile , 'a', encoding="utf-8") as f:
                        f.write(f"\r\n\n{msg}\n")
                if smtp_enabled:
                    sendmail(From, To, msg, "")
                if syslog_enabled:
                    syslog(message="    " + msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def scan_net_ip():

    """
    Function to scan a network using ping for IPs alive ot not
    """

    ipal.clear()
    ipna.clear()

    # Convert IP addresses to integers
    start = list(map(int, IP_START.split('.')))
    end   = list(map(int, IP_END.split('.')))

    # Generate IP range
    for i in range(start[0], end[0] + 1):
        for j in range(start[1], end[1] + 1):
            for k in range(start[2], end[2] + 1):
                for l in range(start[3], end[3] + 1):
                    ip = f"{i}.{j}.{k}.{l}"
                    print(f"\r{SPACES}\r", end="", flush=True)
                    print(f"      IP: {ip}", end="", flush=True)
                    pinger = Pinger(target_host=ip, count=ping_count, size=ping_length, timeout=ping_timeout, debug=DEBUG)
                    tmin, tmax, tavg, lost = pinger.ping()
                    if lost != 100:
                        ipal.append(ip)
                    else:
                        ipna.append(ip)

    print(f"\r{SPACES}\r", end="", flush=True)
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def scan_net_arp(network):

    """
    Function to scan a network using ARP for IPs alive or not
    """

    global arpalive

    arpalive = []

    try:
        # Create an ARP request packet for the specified IP range.
        arp_request = ARP(pdst=str(network))

        # Create an Ethernet frame to broadcast the ARP request.
        # `dst="ff:ff:ff:ff:ff:ff"` is the broadcast MAC address.
        broadcast_ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

        # Combine the Ethernet and ARP packets into one.
        # The `/` operator in Scapy layers the packets.
        arp_request_broadcast = broadcast_ether_frame / arp_request

        # Send the packet and capture the responses.
        # `timeout` specifies how long to wait for a response in seconds
        # `verbose=False` suppresses scapy's default output.
        answered_packets, unanswered_packets = srp(arp_request_broadcast, timeout=arp_timeout, verbose=False)

        for sent, received in answered_packets:
            arpalive.append({'ip': received.psrc, 'mac': received.hwsrc})

        if DEBUG:
            if arpalive:
                for ap in arpalive:
                    print(f" {ap['ip']:<15}    {ap['mac']}")
            else:
                print("No devices found.")

        return arpalive

    except ImportError:
        print("Scapy is not installed. Please install it using 'pip install scapy'.")
        print("Make sure you also install Npcap from https://npcap.com/#download.")
        sys.exit(5)

    except:
        return []
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def scan_port(ip, port, append):

    """
    Function attempts to connect to a given port on the target host
    If the connection is successful, the port is considered open
    """

    try:
        print(f"{'\b' * 5}{port:>5}", end="", flush=True)

        # Create a new socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for the connection attempt
        sock.settimeout(port_timeout)
        # Attempt to connect to the port
        result = sock.connect_ex((ip, port))
        sock.close()

        # connect_ex() returns 0 if the connection is successful
        if result == 0:
            if append:
                with thread_lock:
                    if DEBUG:
                        print(f"{ip} : port {port} is open")
                    ports_open.append(port)
            else:
                return True
            sock.close()
        else:
            sock.close()

    except:
        # An exception can occur if the host is unreachable or due to other network issues
        pass

    finally:
        sock.close()
#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def scan_ip_ports(ip, port_start, port_end):

    """
    Function to scan an IP addrees
    """

    global port_threads
    global ports_open

    ports_open = []

    print(f"\r{SPACES}\r", end="", flush=True)
    if list_count > 0 and list_cntr > 0:
        print(f"    Scanning {ip} ({list_cntr} of {list_count}) for open ports between {port_start} and {port_end}:      ", end="", flush=True)
    else:
        print(f"    Scanning {ip} for open ports between {port_start} and {port_end}:      ", end="", flush=True)

    # Add all ports to the queue
    for port in range(port_start, port_end + 1):
        port_queue.put(port)

    # Create and start the threads
    port_threads = []
    for _ in range(portthread_count):
        th = threading.Thread(target=port_threadworker, args=(ip, port))
        th.start()
        port_threads.append(th)

    # Wait for all threads to complete
    port_queue.join()

    print(f"\r{SPACES}\r", end="", flush=True)

    if DEBUG:
        print("\nScan completed.")
        if ports_open:
            print("Open ports:", sorted(ports_open))
        else:
            print("No open ports found.")
#---------------------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------------------
def log2mdns(IP_NET, IP_MASK):

    """
    Function to write all info to a .mdns file
    """

    services_published, services_ips = services_count(mDNS_listed)

    with open(mDNSfile, "w", encoding="utf-8") as f:
        nwk  = str(network)
        ntip = str(network.network_address)
        ntmk = str(network.netmask)
        timestamp = datetime.now().strftime("%Y-%m-%d")
        f.write( "##################################################\n")
        f.write(f"### File created by {strScriptBase:<26} ###\n")
        f.write(f"###                 Version: {VERSION:<17} ###\n")
        f.write(f"### File created on {timestamp:<26} ###\n")
        f.write( "##################################################\n")
        f.write(f"### Network: {IP_NET:<15} {IP_MASK:<15}   ###\n")
        f.write(f"###          {nwk:<18}                ###\n")
        f.write(f"###          {ntip:<15} {ntmk:<15}   ###\n")
        f.write(f"###          {IP_START:<15} {IP_END:<15}   ###\n")
        f.write( "##################################################\n")
        f.write( "\n\n")

        #............................................................................................................

        if mDNS_unlisted:
            f.write(f"Services unlisted but broadcasted. To be added to YAML file {YAMLfile}\n")
            f.write( "-----------------------------------------------------------------------------------\n")
            for service, details in mDNS_unlisted.items():
                line = f"Service: {"":<35} ({service})\n"
                ip = ""
                for device in details.devices:
                    if ip != device.ip:
                        ip = device.ip
                        host = device.host
                        port =  device.port
                        extra = f"<weight: {device.weight:>2} - priority: {device.priority:>2} - text: {device.text}>"
                        if device.props:
                            props = ", ".join(device.props)
                            if ignore_extra(props, extra):
                                line = line + f"  {host:<45} on <{ip:<15}> listing on port <{port:>5}> with properties [{props}]\n"
                            else:
                                line = line + f"  {host:<45} on <{ip:<15}> listing on port <{port:>5}> with properties [{props}] - Extra info: {extra}\n"
                        else:
                            if is_empty_extra(extra):
                                line = line + f"  {host:<45} on <{ip:<15}> listing on port <{port:>5}>\n"
                            else:
                                line = line + f"  {host:<45} on <{ip:<15}> listing on port <{port:>5}> Extra info: {extra}\n"
                f.write(f"{line}\n")

                st = service.rstrip(".")
                f.write(f"    - name: <WRITE A SERVICE RELATED NAME HERE>\n      service: {st}\n      description: \n\n")
            f.write("\n\n")

        #............................................................................................................

        f.write(f"Hosts broadcasting services ({services_ips:>3})\n")
        f.write("---------------------------------\n")

        # Collect all device entries with service context
        entries = []
        for service, details in mDNS_listed.items():
            if details.devices:
                for device in details.devices:
                    if device.props:
                        props = ", ".join(device.props)
                    else:
                        props = ""
                    entries.append({
                        "ip": device.ip,
                        "host": device.host.split('.')[0].lower(),
                        "port": device.port,
                        "service": service,
                        "name": details.name,
                        "props": props,
                        "weight": device.weight,
                        "priority": device.priority,
                        "text": device.text
                    })

        # add unlisted ones as well
        ip = ""
        port = 0
        for service, details in mDNS_unlisted.items():
            for device in details.devices:
                if ip != device.ip:
                    ip = device.ip
                    if port != device.port:
                        port = device.port
                        if device.props:
                            props = ", ".join(device.props)
                        else:
                            props = ""
                        entries.append({
                            "ip": device.ip,
                            "host": device.host,
                            "port": device.port,
                            "service": service,
                            "name": "",
                            "props": props,
                            "weight": device.weight,
                            "priority": device.priority,
                            "text": device.text
                        })

        # Sort by IP
        entries.sort(key=lambda x: x["ip"])

        ip = ""
        port = 0
        service = ""
        for entry in entries:
            line = ""
            if ip != entry['ip']:
                ip = entry['ip']
                port = entry['port']
                service = entry['service'].lower()
                extra = f"<weight: {entry['weight']:>2} - priority: {entry['priority']:>2} - text: {entry['text']}>"
                line = f"\n{entry['ip']:<15} - {entry['host']:<40}  Port: {entry['port']:>5} - Service: {entry['name']:<40} ({entry['service']:<30})"
            else:
                if port != entry['port'] or service != entry['service'].lower():
                    port = entry['port']
                    service = entry['service'].lower()
                    line = f"{"":<58}  Port: {entry['port']:>5} - Service: {entry['name']:<40} ({entry['service']:<30})"
            if entry["props"] and len(line) > 0:
                line = line + f" with properties [{entry["props"]}]"
            if len(line) > 0:
                if ignore_extra(props, extra):
                    f.write(f"{line}\n")
                else:
                    if is_empty_extra(extra):
                        f.write(f"{line}\n")
                    else:
                        f.write(f"{line}\n{' ' * 157}Extra info: {extra}\n")


        f.write("\n\n")

        #............................................................................................................

        f.write(f"Services being broadcasted  ({services_published})\n")
        f.write("--------------------------------\n")
        for service, details in mDNS_listed.items():
            line = ""
            if details.devices:
                line = f"Service: {details.name:<35} ({service})\n"
                ip = ""
                for device in details.devices:
                    if ip != device.ip:
                        ip = device.ip
                        host = device.host.split('.')[0].lower()
                        props = ", ".join(device.props)
                        extra = f"<weight: {device.weight:>2} - priority: {device.priority:>2} - text: {device.text}>"
                        if props:
                            if ignore_extra(props, extra):
                                line = line + f"  {host:<45} on <{device.ip:<15}> listing on port <{device.port:>5}> with properties [{props}]\n"
                            else:
                                line = line + f"  {host:<45} on <{device.ip:<15}> listing on port <{device.port:>5}> with properties [{props}]\n{' ' * 93}Extra info: {extra}\n"
                        else:
                            if is_empty_extra(extra):
                                line = line + f"  {host:<45} on <{device.ip:<15}> listing on port <{device.port:>5}>\n"
                            else:
                                line = line + f"  {host:<45} on <{device.ip:<15}> listing on port <{device.port:>5}>\n{' ' * 93}Extra info: {extra}\n"
                f.write(f"{line}\n")
        f.write("\n")

#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def log2net(net, mask, network):

    """
    Function to write all info to a .net file
    """

    global netports_open

    ipnet = []

    with open(NETfile, 'w', encoding="utf-8") as f:
        l    = len(ipalive)
        nwk  = str(network)
        ntip = str(network.network_address)
        ntmk = str(network.netmask)
        timestamp    = datetime.now().strftime("%Y-%m-%d")
        f.write( "##################################################\n")
        f.write(f"### File created by {strScriptBase:<26} ###\n")
        f.write(f"###                 Version: {VERSION:<17} ###\n")
        f.write(f"### File created on {timestamp:<26} ###\n")
        f.write( "##################################################\n")
        f.write(f"### Network: {IP_NET:<15} {IP_MASK:<15}   ###\n")
        f.write(f"###          {nwk:<18}                ###\n")
        f.write(f"###          {ntip:<15} {ntmk:<15}   ###\n")
        f.write(f"###          {IP_START:<15} {IP_END:<15}   ###\n")
        if netportscan_enabled:
            f.write( "##################################################\n")
            f.write(f"### Portscan from {netport_start:>5} to {netport_end:>5}               ###\n")
        f.write( "##################################################\n")
        f.write("\n\n")

        #............................................................................................................

        f.write(f"IPs alive ({l:>3})\n")
        f.write( "---------------\n")

        for ipdict in ipalive:

            ip_15 = ipdict['ip']

            ip = reformat_ip(ip_15, False)

            # find hostname in DNS
            hostname = ipdict['hostname'].lower()
            if hostname == "":
                hostname = "<not in DNS>"
                try:
                    hostname = socket.gethostbyaddr(ip)[0].lower()
                except socket.herror:
                    hostname = "<not in DNS>"
                    if ip_15 in ScanDict:
                        hostname = ScanDict[ip_15].lower()
            hostname = hostname.split('.')[0].lower()

            mac = ipdict['mac']
            if mac == "":
                if host_net:
                    if ip != host_ip:
                        # Run the arp command to get the MAC address
                        arp_command = ['arp', '-a', ip]
                        output = subprocess.check_output(arp_command).decode()
                        # Use regex to find the MAC address in the output
                        mac_address = re.search(r'(([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2})', output)
                        if mac_address:
                            mac = mac_address.group(0).replace('-', ':')
                        else:
                            mac = ""
                    else:
                        mac = host_mac

            netports_open  = []
            ports_print = ""
            if 'ports' in ipdict:
                netports_open = ipdict['ports']

            if netports_open:
                if netportdesc_enabled:
                    ports_list = []
                    for port in netports_open:
                        if port in PortsDict:
                            desc = PortsDict[port]
                        else:
                            desc = "Dynamic/Private"
                        ports_list.append(f"{port} ({desc})")
                    ports_print = ', '.join(ports_list)
                else:
                    ports_print = ', '.join(netports_open)
            else:
                ports_print = ""

            line = f"{ip_15:<15} - {hostname:<40}  {mac:<17}"
            if ports_print != "":
                line = line + f"  Open Ports: {ports_print}"
            f.write(f"{line}\n")
            ipnet.append(line)

        #............................................................................................................

        for ip in ipna:
            ip_15 = reformat_ip(ip, True)
            hostname = ""
            if ip_15 in ScanDict:
                hostname = ScanDict[ip_15].lower()
                line = f"{ip_15:<15} - {hostname:<36}  !!!!    NOT ALIVE   !!!!"
            else:
                line = f"{ip_15:<15}"
            ipnet.append(line)

        ipnet.sort(key=lambda x: x[:15])

        u = len(ipnet) - l
        f.write(f"\n\nIP inventory  ({l:>4} used, {u:>4} unused)\n")
        f.write("--------------------------------------\n")
        for item in ipnet:
            f.write(f"{item}\n")
        f.write("\n\n")

#---------------------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------
def log2txt(net, mask, network):

    """
    Function to write all info to a .txt file
    """

    with open(TXTfile , 'w', encoding="utf-8") as f:
        nwk  = str(network)
        ntip = str(network.network_address)
        ntmk = str(network.netmask)
        timestamp    = datetime.now().strftime("%Y-%m-%d")
        f.write( "##################################################\n")
        f.write(f"### File created by {strScriptBase:<26} ###\n")
        f.write(f"###                 Version: {VERSION:<17} ###\n")
        f.write(f"### File created on {timestamp:<26} ###\n")
        f.write( "##################################################\n")
        f.write(f"### Network: {net:<15} {mask:<15}   ###\n")
        f.write(f"###          {nwk:<18}                ###\n")
        f.write(f"###          {ntip:<15} {ntmk:<15}   ###\n")
        f.write(f"###          {IP_START:<15} {IP_END:<15}   ###\n")
        if netportscan_enabled:
            f.write( "##################################################\n")
            f.write(f"### Portscan from {listport_start:>5} to {listport_end:>5}               ###\n")
        f.write( "##################################################\n")
        f.write( "### Format: hostname;IP-address;Status;Ports:  ###\n")
        f.write( "### Status: A = Active or O = occasionally     ###\n")
        f.write( "### Ports: comma separated list of open ports  ###\n")
        f.write( "##################################################\n")
        f.write("\n\n")

        #............................................................................................................


        # First, normalize the 'hostname' values to lowercase, using a default if missing
        for ipdict in ipalive:
            ipdict['hostname'] = ipdict.get('hostname', "<not in DNS>").lower()

        ipalive.sort(key=lambda x: x['hostname'])

        for ipdict in ipalive:

            ip_15 = ipdict['ip']

            ip = reformat_ip(ip_15, False)

            # find hostname in DNS
            hostname = ipdict['hostname']
            if hostname == "":
                hostname = "<not in DNS>"
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = ScanDict.get(ip_15, "<not in DNS>")

            hostname = hostname.split('.')[0].lower()

            listports_open = []
            ports_print = ""
            if 'ports' in ipdict:
                listports_open = ipdict['ports']

            if listports_open:
                listports_open.sort()
                # Check if all elements are integers
                if all(isinstance(port, int) for port in listports_open):
                    ports_print = ', '.join(str(port) for port in listports_open)
                elif all(isinstance(port, str) for port in listports_open):
                    ports_print = ', '.join(listports_open)
                    ports_print = re.sub(r"\s*\([^)]*\)", "", ports_print)
            else:
                ports_print = ""

            f.write(f"{hostname};{ip};A;Ports: {ports_print}\n")

        f.write("\n\n")

        #............................................................................................................

        # some extra checks for the healty of your network
        f.write("################################################\n")
        f.write("### External netwerks\n")
        f.write("################################################\n")
        f.write("#-----------------------------------------------\n")
        f.write("# DNS Google\n")
        f.write("#-----------------------------------------------\n")
        f.write("dns.google;8.8.8.8;A\n")
        f.write("#-----------------------------------------------\n")
        f.write("# DNS OpenDNS\n")
        f.write("#-----------------------------------------------\n")
        f.write("dns.umbrella.com;208.67.222.222;A\n")
        f.write("#-----------------------------------------------\n")
        f.write("# DNS EU\n")
        f.write("#-----------------------------------------------\n")
        f.write("protective.joindns4.eu;86.54.11.1;A\n")
        f.write("child-noads.joindns4.eu;86.54.11.11;A\n")
        f.write("child.joindns4.eu;86.54.11.12;A\n")
        f.write("noads.joindns4.eu;86.54.11.13;A\n")
        f.write("unfiltered.joindns4.eu;86.54.11.100;A\n")
        f.write("\n\n")

#---------------------------------------------------------------------------------------------------


####################################################################################################
### Main
####################################################################################################

if __name__ == "__main__":

    try:
        # Build a mapping from GUID to friendly name
        print(f"{strScriptBase} Version: {VERSION} written by Marc Engrie\n", flush=True)
        print(f"  running on {COMPUTERNAME} with active network interfaces", flush=True)

        # Get all network interfaces
        interfaces_addrs = psutil.net_if_addrs()
        # Get network interface statistics
        interfaces_stats = psutil.net_if_stats()

        # Iterate through each interface
        for interface_name, addresses in interfaces_addrs.items():
            if interfaces_stats.get(interface_name, None).isup:
                # Iterate through the addresses for the current interface
                for address in addresses:
                    if address.family == socket.AF_INET:  # IPv4 address
                        ip = address.address
                        # ignore localhost = 127.0.0.1
                        if ip != "127.0.0.1":
                            mask    = address.netmask
                            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                            print(f"    IP: {ip:<15}  Netmask: {mask:<15}  Network: {str(network):<20}   Adapter: {interface_name}")
                    # elif address.family == socket.AF_INET6: # IPv6 address
                        # print(f"  IPv6 Address: {address.address}")
                    # elif address.family == psutil.AF_LINK: # MAC address
                        # print(f"  MAC Address: {address.address}")
        print("")

        #----------------------------------------------------------------------------------------------------------------
        ## get command line arguments
        #----------------------------------------------------------------------------------------------------------------
        getargs(sys.argv[1:])
        #----------------------------------------------------------------------------------------------------------------

        #----------------------------------------------------------------------------------------------------------------
        ## load YAML file
        #----------------------------------------------------------------------------------------------------------------
        with open(YAMLfile, 'r', encoding="utf-8") as file:
            config = yaml.safe_load(file)

        ## Reporting
        if "SCREENLOG" in config:
            screen_enabled = config['SCREENLOG']['Enabled']

        if "FILELOG" in config:
            logfile_enabled = config['FILELOG']['Enabled']

        if "SMTPLOG" in config:
            smtp_enabled = config['SMTPLOG']['Enabled']
            if smtp_enabled:
                smtp_config   = config['SMTPLOG']
                smtpserver    = smtp_config['Server']
                smtpport      = smtp_config['Port']
                smtptls       = smtp_config['TLS']
                smtpCA        = smtp_config['CA']
                smtplogin     = smtp_config['Login']
                smtppass      = smtp_config['Password']
                From          = smtp_config['From']
                To            = smtp_config['To']
                if DEBUG:
                    sendmail(From, To, 'Testmail',"")

        if "SYSLOG" in config:
            syslog_enabled = config['SYSLOG']['Enabled']
            if syslog_enabled:
                syslog_config = config['SYSLOG']
                syslogserver  = syslog_config['Server']
                syslogport    = syslog_config['Port']

        ## Scanning
        if "PINGSCAN" in config:
            ping_config = config['PINGSCAN']
            ping_count = ping_config.get('Count', ping_count)
            if not isinstance(ping_count, (int)):
                print("FATAL: Count requires numeric argument.", file=sys.stderr)
                sys.exit(6)
            ping_length = ping_config.get('Length', ping_length)
            if not isinstance(ping_length, (int)):
                print("FATAL: Length requires numeric argument.", file=sys.stderr)
                sys.exit(7)
            ping_timeout = ping_config.get('Timeout', ping_timeout)
            if not isinstance(ping_timeout, (int)):
                print("FATAL: Timeout requires numeric argument.", file=sys.stderr)
                sys.exit(8)

        if "ARPSCAN" in config:
            arp_config = config['ARPSCAN']
            arpscan_enabled = arp_config['Enabled']
            if arpscan_enabled:
                arp_timeout = arp_config.get('Timeout', arp_timeout)
                if not isinstance(arp_timeout, (int)):
                    print("FATAL: ARP Timeout requires numeric argument.", file=sys.stderr)
                    sys.exit(9)

                service_name = "npcap"
                if not is_service_running(service_name):
                    arpscan_enabled = False
                    print(f"    !!! Important Note !!! {service_name.upper()} is not running. No ARP scanning will be done")
                    msg =  f"ARP scanning DISABLED as {service_name.upper()} is not running !!!"
                    if logfile_enabled:
                        with open(LOGfile , 'a', encoding="utf-8") as f:
                            f.write(f"\r\n\n{msg}\n")
                    if smtp_enabled:
                        sendmail(From, To, msg, "")
                    if syslog_enabled:
                        syslog(message=f"  {msg}", host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

        if "PORTSCAN" in config:
            port_config   = config['PORTSCAN']
            port_advisory = port_config.get('Advisory', port_advisory)
            port_timeout  = port_config.get('Timeout', port_timeout)
            if not isinstance(port_timeout, (int)):
                print("FATAL: Port Timeout requires numeric argument.", file=sys.stderr)
                sys.exit(9)
            portthread_count = port_config.get('Threads', portthread_count)
            if not isinstance(portthread_count, (int)):
                print("FATAL: Port Thread Count requires numeric argument.", file=sys.stderr)
                sys.exit(9)

        if "NETSCAN" in config:
            netscan_config  = config['NETSCAN']
            netscan_enabled = netscan_config['Enabled']
            if netscan_enabled:
                netportscan_enabled = config['NETSCAN']['Portscan']
                if netportscan_enabled:
                    netport_start       = netscan_config.get('Start', netport_start)
                    netport_end         = netscan_config.get('End', netport_end)
                    netportdesc_enabled = netscan_config.get('PortDesc', netportdesc_enabled)

        if "LISTSCAN" in config:
            listscan_config  = config['LISTSCAN']
            listscan_enabled = listscan_config['Enabled']
            if listscan_enabled:
                if ScanList == "":
                    ScanList = os.path.join(strScriptPath, strScriptBase + f"_{IP_NET}.lst")
                    if not os.path.exists(ScanList):
                        ScanList = ""
                        listscan_enabled = False
            if listscan_enabled:
                # Get line count
                with open(ScanList, 'r', encoding="utf-8") as f:
                    list_count = sum(
                        1 for line in f
                        if line.strip() and not line.strip().startswith('#')
                )
                listportscan_enabled = listscan_config['Portscan']
                if listportscan_enabled:
                    listport_start       = listscan_config.get('Start', listport_start)
                    listport_end         = listscan_config.get('End', listport_end)
                    listportdesc_enabled = listscan_config.get('PortDesc', listportdesc_enabled)

        if "MDNSSCAN" in config:
            mDNS_config = config['MDNSSCAN']
            mDNSscan_enabled = mDNS_config['Enabled']
        #----------------------------------------------------------------------------------------------------------------

        #----------------------------------------------------------------------------------------------------------------
        # load extra data from YAML-file if needed
        #----------------------------------------------------------------------------------------------------------------
        if netportdesc_enabled or listportdesc_enabled:
            if "PORTS" in config:
                PortsDict = config['PORTS']

        if mDNSscan_enabled:
            mDNS_timeout = mDNS_config.get('Timeout', mDNS_timeout)
            if "MDNS" in config:
                mDNSList = config["MDNS"].get("Services", [])
                for entry in mDNSList:
                    # normalize to lower making sure ending with a .
                    service = entry["service"].lower()
                    if not service.endswith('.'):
                        service += '.'
                    entry["service"] = service
                # sort
                mDNSList.sort(key=lambda x: x["name"])
                # convert to dictionary
                for entry in mDNSList:
                    mDNS_listed[entry["service"]] = Service(name=entry["name"], devices=[])
        #----------------------------------------------------------------------------------------------------------------

        #----------------------------------------------------------------------------------------------------------------
        ## delete files, if exists
        #----------------------------------------------------------------------------------------------------------------
        if os.path.exists(NETfile):
            os.remove(NETfile)

        if not listscan_enabled :
            TXTfile = NETfile.replace(".net", ".txt")
            if os.path.exists(TXTfile):
                os.remove(TXTfile)

        if logfile_enabled:
            LOGfile = NETfile.replace(".net", ".err")
            if os.path.exists(LOGfile):
                os.remove(LOGfile)

        if mDNSscan_enabled:
            mDNSfile = NETfile.replace(".net", ".mdns")
            if os.path.exists(mDNSfile):
                os.remove(mDNSfile)
        #----------------------------------------------------------------------------------------------------------------

        #----------------------------------------------------------------------------------------------------------------
        ## scanning a routed network or a non-routed network?
        #----------------------------------------------------------------------------------------------------------------

        # init some vars
        addr_lst = []
        mask_lst = []
        IP_START  = ""
        IP_END    = ""
        host_net = False

        # check if one of host interface is within IP_NET
        netifs=netifaces.interfaces()
        for netif in netifs:
            netifaddr = netifaces.ifaddresses(netif)
            if netifaces.AF_INET in netifaddr:
                ip   = netifaddr[netifaces.AF_INET][0]["addr"]
                mask = netifaddr[netifaces.AF_INET][0]["netmask"]
                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                if str(network).startswith(IP_NET):
                    host_ip   = netifaddr[netifaces.AF_INET][0]["addr"]
                    host_mac  = netifaddr[netifaces.AF_LINK][0]['addr'].upper()
                    host_net  = True
                    addr_lst  = ip.split('.')
                    mask_lst  = mask.split('.')
                    break
                if DEBUG:
                    print(f"    Found local Net {ip:<15} -->> skipping this network")

        # if scan is not within host network
        # this also means scan is in a routed network
        if not host_net :
            if IP_MASK == "":
                IP_MASK = "255.255.255.0"
            network = extend_ip(IP_NET, IP_MASK)
            if DEBUG:
                print(f"Extended IP: {network.network_address}")
                print(f"Network: {network}")
            # ARP scanning in a routed network makes no sense
            if arpscan_enabled:
                arpscan_enabled = False
            # mDNS scanning in a routed network makes no sense
            if mDNSscan_enabled:
                mDNSscan_enabled = False

        IP_START = str(list(network.hosts())[0])
        IP_END   = str(list(network.hosts())[-1])
        #----------------------------------------------------------------------------------------------------------------

        #----------------------------------------------------------------------------------------------------------------
        ## show what will be done
        #----------------------------------------------------------------------------------------------------------------
        if syslog_enabled:
            msg = f"Start of {strScriptBase}"
            syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

        msg = ""
        msg = msg +  "  running with options:\n"
        msg = msg + f"    Net to scan  : <{IP_NET}>\n"
        msg = msg + f"    Using YAML   : <{YAMLfile}>\n"

        net_priv = is_private_network(str(network))

        if net_priv:
            if port_advisory:
                port_scanning_advisory()
                print("\n")
        else:
            print("  ################################################################################\n")
            print("  !!! IMORTANT NOTICE !!!\n  You are going to scan a public network\n  Therefor port scanning will be disabled\n")
            port_scanning_advisory()
            print("\n")

            netportscan_enabled  = False
            listportscan_enabled = False

        if not host_net:
            if net_priv:
                msg = msg + f"    Network <{network}> is a routed private network\n"
            else:
                msg = msg + f"    Network <{network}> is a routed public network\n"
        else:
            if net_priv:
                msg = msg + f"    Network <{network}> is a non-routed private network\n"
            else:
                msg = msg + f"    Network <{network}> is a non-routed public network\n"

        if netscan_enabled:
            msg = msg + "    Full Scan enabled "
            if netportscan_enabled:
                msg = msg + f"with Port Scan from <{netport_start}> to <{netport_end}>\n"
            else:
                msg = msg + "with Port Scan disabled\n"

        if listscan_enabled and ScanList != "":
            msg = msg + f"    List Scan using <{ScanList}> ({list_count} entries) "
            if listportscan_enabled:
                msg = msg + f"with Port Scan from <{listport_start}> to <{listport_end}>\n"
            else:
                msg = msg + "with Port Scan disabled\n"
        msg = msg + f"    ARP  scanning: <{BOOLEAN_MAP[arpscan_enabled]}>"

        if not arpscan_enabled and not host_net:
            msg = msg + " (not possible in routed network)\n"
        else:
            msg = msg + "\n"
        msg = msg + f"    mDNS scanning: <{BOOLEAN_MAP[mDNSscan_enabled]}>"

        if not mDNSscan_enabled and not host_net:
            msg = msg + " (not possible in routed network)"
        else:
            if mDNSscan_enabled:
                tot = len(mDNS_listed)
                msg = msg + f" ({tot} services listed)"

        print(msg)

        if syslog_enabled:
            syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)
        #----------------------------------------------------------------------------------------------------------------

        #----------------------------------------------------------------------------------------------------------------
        #clear local dns cache
        #----------------------------------------------------------------------------------------------------------------
        flush_ipcache()
        #----------------------------------------------------------------------------------------------------------------

        #----------------------------------------------------------------------------------------------------------------
        ## should we do a mDNS services scan first?
        #----------------------------------------------------------------------------------------------------------------
        # can only do a mDNS services scan if in non-routed network
        if mDNSscan_enabled and host_net:

            #............................................................................................................

            msg = "  Start of mDNS service scan"
            if syslog_enabled:
                syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

            zeroconf = Zeroconf(ip_version=IPVersion.V4Only)

            print("\n  Searching for all mDNS services being published", end="", flush=True)

            listener = MyListener(zeroconf, mDNS_listed)
            browser  = ServiceBrowser(zeroconf, "_services._dns-sd._udp.local.", listener)

            countdown = mDNS_timeout
            start = time.time()
            mDNS_timeend = start + mDNS_timeout
            print(f" - waiting another {countdown:>3} sec", end="", flush=True)
            while True:
                if time.time() - start > 1:
                    countdown -= 1
                    print(f"{'\b' * 7}{countdown:>3} sec", end="", flush=True)
                    start = time.time()
                if start >= mDNS_timeend:
                    break

            print(f"{'\b' * 26}{' ' *31}\n", end="", flush=True)

            mDNS_unlisted = listener.unlisted_services

            zeroconf.close()

            services_published, services_ips = services_count(mDNS_listed)

            msg = f"    Scanning for all mDNS services completed. Found {services_ips} devices publishing {services_published} serivces"
            if mDNS_unlisted:
                msg = msg + f" of which {len(mDNS_unlisted)} unlisted services\n"
            else:
                msg = msg + ". No unlisted services found\n"
            print(msg)

            st = ""
            for service, details in mDNS_unlisted.items():
                if st != service:
                    st = service
                    body = ""
                if details.devices:
                    for device in details.devices:
                        txt = f"{service:<35}: {device.ip:<15} - {device.host:<45} - Port: {device.port:>5}"
                        if DEBUG:
                            print(txt)
                        body = body + txt + "\n"
                msg =  f"mDNS service {st} not in list of known mDNS services"
                if screen_enabled:
                    print(f"\r\n      {msg}\n      {body}\n")
                if logfile_enabled:
                    with open(LOGfile , 'a', encoding="utf-8") as f:
                        f.write(f"\r\n\n{msg}\n  {body}\n")
                if smtp_enabled:
                    sendmail(From, To, msg, body)
                if syslog_enabled:
                    syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

            #............................................................................................................

            log2mdns(IP_NET, IP_MASK)

            # create dictionary with IPs as keys and mDNS ports open for the ip address
            ports_mdns = defaultdict(list)
            for service in mDNS_listed.values():
                for device in service.devices:
                    ip = device.ip
                    port = device.port
                    if port not in ports_mdns[ip]:
                        ports_mdns[ip].append(port)

            # add unlisted ones
            for service, details in mDNS_unlisted.items():
                for device in details.devices:
                    ip = device.ip
                    port = device.port
                    if port not in ports_mdns[ip]:
                        ports_mdns[ip].append(port)
            ports_mdns = dict(ports_mdns)

            # Sort the dictionary by IP address
            ports_mdns = dict(sorted(ports_mdns.items(), key=lambda item: ip_to_tuple(item[0])))

            msg = "  End   of mDNS service scan\n"
            if syslog_enabled:
                syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)
        #----------------------------------------------------------------------------------------------------------------

        #----------------------------------------------------------------------------------------------------------------
        ## scan entire network requested
        #----------------------------------------------------------------------------------------------------------------
        if netscan_enabled:
            msg = f"  Start of full scan network {IP_NET} - {IP_MASK}"
            if syslog_enabled:
                syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

            #............................................................................................................

            print(f"  Full Scan from {IP_START} to {IP_END}")

            scan_net_ip()

            if netportscan_enabled:
                for ip in ipal:
                    netports_open = []
                    scan_ip_ports(ip, netport_start, netport_end)
                    netports_open = ports_open
                    ip_15 = reformat_ip(ip, True)
                    if ports_mdns:
                        if ip_15 in ports_mdns:
                            netports_open = netports_open + ports_mdns[ip_15]
                            # remove possible duplicates
                            seen = set()
                            i = 0
                            while i < len(netports_open):
                                if netports_open[i] in seen:
                                    # remove duplicate
                                    del netports_open[i]
                                else:
                                    seen.add(netports_open[i])
                                    i += 1
                    netports_open.sort()
                    ipalive.append({'ip': ip_15, 'hostname': '', 'mac': '', 'ports': netports_open})
            else:
                netports_open = []
                for ip in ipal:
                    ip_15 = reformat_ip(ip, True)
                    if ports_mdns:
                        netports_open = ports_mdns.get(ip_15, [])

                    netports_open.sort()
                    ipalive.append({'ip': ip_15, 'hostname': '', 'mac': '', 'ports': netports_open})

            #............................................................................................................

            # only do arp scan if within same segement = non-routed
            if host_net and arpscan_enabled:

                scan_net_arp(network)

                # Iterate through ipalive and update mac if ip matches
                if arpalive:
                    for ipdict in ipalive:
                        ip_val = ipdict['ip']
                        for apdict in arpalive:
                            if apdict['ip'] == ip_val:
                                ipdict['mac'] = apdict['mac']
                                break

                    # Remove enrties from arpalive if ip already exists in ipal
                    arpalive = [entry for entry in arpalive if entry["ip"] not in ipal]

                    if DEBUG:
                        print("Updated ipalive:")
                        print(ipalive)

                    for apdict in arpalive:
                        ip  = apdict['ip']
                        mac = apdict['mac']
                        if netportscan_enabled:
                            netports_open = []
                            scan_ip_ports(ip, netport_start, netport_end)
                            netports_open = ports_open
                            ip_15 = reformat_ip(ip, True)
                            if ports_mdns:
                                if ip_15 in ports_mdns:
                                    netports_open = netports_open + ports_mdns[ip_15]
                                    # remove possible duplicates
                                    seen = set()
                                    i = 0
                                    while i < len(netports_open):
                                        if netports_open[i] in seen:
                                            # remove duplicate
                                            del netports_open[i]
                                        else:
                                            seen.add(netports_open[i])
                                            i += 1
                            netports_open.sort()
                            ipalive.append({'ip': ip_15, 'hostname': '', 'mac': '', 'ports': netports_open})

            #............................................................................................................

            log2net(IP_NET, IP_MASK, network)

            msg = f"  End   of full scan network {IP_NET} - {IP_MASK}"
            if syslog_enabled:
                syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

            print("    Full Scan finished\n")
        #----------------------------------------------------------------------------------------------------------------

        #----------------------------------------------------------------------------------------------------------------
        ## scan based on a list provided?
        #----------------------------------------------------------------------------------------------------------------
        if listscan_enabled:
            msg = f"  Start of list based scan {ScanList}"
            if syslog_enabled:
                syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

            print(f"  List Scan using {ScanList}")

            with open(ScanList, "r", encoding="utf-8") as fh:
                list_cntr = 0
                for line in fh:
                    Host = line.strip()
                    if len(Host) > 0:
                        if Host[0] != '#':
                            list_cntr += 1
                            ScanHost(Host.strip())
            print(f"\r{SPACES}\r", end="", flush=True)

            if ScanHost_cntr == 0:
                print("    List Scan finished. No anomalies found\n")
            else:
                print(f"    List Scan finished. {ScanHost_cntr} anomalies found\n")

            msg = f"  End   of list based scan {ScanList}"
            if syslog_enabled:
                syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

        else:
            if ipalive:
                log2txt(IP_NET, IP_MASK, network)
        #----------------------------------------------------------------------------------------------------------------

        #----------------------------------------------------------------------------------------------------------------
        ## did we forget hosts;ips?
        #----------------------------------------------------------------------------------------------------------------
        if ipalive and ScanList != "":
            
            print("  Checking if unlisted devices are spooking on your network")
            body = ""
            for ipdict in ipalive:
                ip         = ipdict['ip']
                hostname   = ipdict['hostname'].lower()
                mac        = ipdict['mac']

                MAC_host, DNS_host = get_mac_address_and_hostname(ip)

                if hostname == "":
                    if DNS_host:
                        hostname = DNS_host.split('.')[0].lower()

                if mac == "":
                    if MAC_host:
                        mac = MAC_host.upper()

                netports_open = []
                if netportscan_enabled:
                    scan_ip_ports(ip, netport_start, netport_end)
                    netports_open = ports_open
                    ipdict['ports'] = netports_open

                body = body + f"IP address: {ip:<15} - Hostname: {hostname:<20} - MAC address: {mac:<16} - Port: {netports_open}\n"

            tot = len(ipalive)
            print(f"    {tot} devices are spooking on your network")

            msg = "Not listed active IPs\n"
            if smtp_enabled:
                sendmail(From, To,  msg, body)
            if screen_enabled:
                print(f"\r\n\n    {msg}\n")
                for line in body.split("\n"):
                    print(f"      {line}\n      {body}\n")
            if logfile_enabled:
                with open(LOGfile , 'a', encoding="utf-8") as f:
                    f.write(f"\r\n\n  {msg}\n    {body}\n")
                    for line in body.split("\n"):
                        f.write(f"      {line}\n")
        #----------------------------------------------------------------------------------------------------------------

        msg = f"End   of {strScriptBase}"
        if syslog_enabled:
            syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n")
        msg = f"End   of {strScriptBase} !!! Interrupted !!!"
        if syslog_enabled:
            syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)

    # except Exception as e:
        # print(f"An unexpected error occurred: {e}")
        # msg = f"End   of {strScriptBase} !!! ERROR !!!"
        # if syslog_enabled:
            # syslog(message=msg, host=syslogserver, port=syslogport, hostname=COMPUTERNAME, appname=strScriptBase)
