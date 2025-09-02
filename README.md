# Scan-Network (Version 4.00)

Scan-Network is a combination of previous Python scripts Ping-Network.py and ScanNetwork.py which are now obsoleted and will not be maintained anymore. 

The first function of Scan-Network is to ping all IP-addreses in a network. 
You can also enabled ARP-scanning to find devices that did not respond to a ping. 
Once a IP address is responding to a ping or ARP request, a check for a DNS-entry is done.
If you enabled port scanning in the YAML file (see later), a portscan will be executed on all 
IP addresses that responded. 
A file listing all of this information can be generated. 

**Note:** 
  To make use of arp scanning you need Npcap 1.83 or higher to be install on your Windows computer.
  You can download and install it from here https://npcap.com/#download
  If you use the Python version, you need also to install scapy using 

  `pip install scapy`

  ARP scanning will only be doen if the host sits in the same network that yo are scanning.
  It has no sense doing an ARP scan if host only can reach the scanned network through a router

  Port scanning wil only be done if network is private (10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16). 
  Public networks will not be scanned.

The second function of Scan-Network is to ping a provided list of devices to see itf they are alive or not.
Once a IP address is responding to a ping, a check for open ports can be dexecuted and matched against the list of open ports for that IP-address.
Mismataches will be reported.

A .net file is generated listing all IP-addresses in the network you specified. 
The file contains for each device that is alive in your network, its IP-address, its hostname if availble, its MAC-address and a list op open ports. 
IP-addresses not alive are just listed as is. 

The third function of Scan-Network is to check for a list of known mDNS services available in your network.
A report file .mdns is generated so you can see which device is publishing what mDNS service. 

Combining function one and two will also report IP addresses that are not in the list but alive in your network a.k.a. rogue devices.

Reporting can be on screen, to a file, via mail or via syslog or any combination of the 3. 

To control the behavior of Scan-Network, there are some command line arguments as well as a YAML file. 

The command line options are

-D            : optional - Allows you activate Debugging mode

-Y <filename> : optional - the filename of the YAML-file to use. If none is given, Scan-Network.yaml is used

-P <filename> : optional - the filename of the file containing the devices to ping and, eventually, do a portscan

-N <string>   : the partial IP address of the network to scan Eg: 192.168.1  or 10.15.12 

-M <string>   : optional - the netmask to use eg: 255.255.252.0. Default is 255.255.255.0

The YAML file cantains a lot more options. For the content of the YAML-file I refer to the sample included.
It allows to activate or deactivate a arpscan, netscan, a listscan, a portscan or a mDNS scan.
You can also set the range of port to scan, and timeouts as well as ping settings. 
Comment in the YAML-file will help you to understand the meaning of the setting. 

Some run examples

 `python.exe Scan-Network.py -N "192.168.1"`

will run a full scan of the network 192.168.1.0/24 or with netmask "255.255.255.0". So from 192.168.1.1 to 192.168.1.254. 
All devices that reply to a ping, or apr-request if enabled in YAML-file, will be listed in a file called Scan-Network_192.168.1.txt.
If they have a DNS-record in the DNS server used, a hostname will be added. Note to disable LISTSCAN in the YAML file.
A second file Scan-Network_192.168.1.net is created listing all alive IP's with their hostname, if available, and their MAC-address.
In the file you find a second list with all IP's (alive and not responding). So you can see what IPs are still available.

You can edit the .txt file to add or correct as what needed. Then, rename it to Scan-Network_192.168.1.lst.

When you run the tool like this

  `python.exe Scan-Network.py -P "Scan-Network_192.168.1.lst" -N "192.168.1"`

the tool will do a full scan of the network as well as a specific scan of all devices list in Scan-Network_192.168.1.lst. 
Any deivce not responding will be reported. Any device alive and not in the list will also be reported.
idem for ports if port scan was requested.

**Note:** 
Should a device occasionally be online, then you can control the reporting by changing the status-flag in the .lst file from A (always) to O (occasionally)

Reporting of anomalies can be on the screen (PRINT), in a file .err (FILE), mail (SMTP) or via syslog message (SYSLOG). 
All controlled in the corresponding section of the YAML-file

This is a Python script that allows you to scan your network(s).
It can be 'converted' to a Windows .exe file.
As Scan-Network.exe (Version 4.00 or higher) is about 45 MB, I can not upload it to GitHub. 
So contact me if you want a copy or you can make it yourself if you have Python installed

  `pip install pyinstaller`
  `pyinstaller --onefile "Scan-Network.py" --exclude-module pkg_resources`

**A note on duration:**
A full scan of a network of 255 IP-address including a port scan between 1 and 1024 takes about 2 hours.
Increasing port scan to 2048 increases it with another extra 2 hours adding the total runtime to 4 hours.

**A note on port scanning:**
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

Scan-Network will disabled port scanning if the IP-address or network is not a private network but a public network.


Extract from a .lst / .txt sample file
~~~
# Format: hostname;IP-address;Status 
# Status can be A = Active or O = occasionally
################################################
### Internal netwerk - 192.168.1
################################################
#-----------------------------------------------
# Fixed IP
#-----------------------------------------------
router;192.168.1.1;A;Ports: 22, 53, 80
ap-tpwr802n-engrie4;192.168.1.2;A;Ports: 
ap-tpwr802n-lepouttre343;192.168.1.3;A;Ports:
ap-tplinkeap615L;192.168.1.4;A;Ports: 80
pl-tplinkwpa7510G;192.168.1.5;A;Ports: 80
ap-tplinkeap225B;192.168.1.6;A;Ports: 80
ap-tplinkeap115B;192.168.1.7;A;Ports: 80
ap-tplinkeap615G;192.168.1.8;A;Ports: 80
devolo-5400;192.168.1.9;A;Ports: 80
sw-netgeargs116eB;192.168.1.10;A;Ports: 80
sw-netgeargs308eppB;192.168.1.11;A;Ports: 80
sw-netgeargs308eppG;192.168.1.12;A;Ports: 80
sw-netgeargs305eppK;192.168.1.13;A;Ports: 80
storage1;192.168.1.16;A;Ports: 80
storage2;192.168.1.17;A;Ports: 21, 22, 80
octopi;192.168.1.66;O;Ports: 80

#-----------------------------------------------
# DHCP reservations
#-----------------------------------------------
chromecast-bedroom;192.168.1.61;A;Ports:
daikin-bedroom;192.168.1.103;A;Ports: 80
daikin-bureau;192.168.1.107;A;Ports: 80
daikin-keuken;192.168.1.47;A;Ports: 80
daikin-living;192.168.1.68;A;Ports: 80
dell5580-marleen;192.168.1.53;A;Ports: 
~~~


Extract from a sample .net file
~~~
##################################################
### File created by Scan-Network               ###
###                 Version: 4.00              ###
### File created on 2025-08-23                 ###
##################################################
### Network: 192.168.1       255.255.255.0     ###
###          192.168.1.0/24  255.255.255.0     ###
##################################################
### Portscan from     1 to 1024                ###
##################################################

IPs alive ( 70)
---------------
192.168.001.001 - router                                    00:11:32:bf:d2:75  Open Ports: 22 (SSH), 53 (DNS), 80 (HTTP), 139 (NETBIOS Session Service), 161 (SNMP), 445 (Microsoft-DS), 443 (HTTPS), 515 (spooler)
192.168.001.002 - ap-tpwr802n-engrie4                       78:8c:b5:d3:de:5d
192.168.001.003 - ap-tpwr802n-lepouttre343                  9c:53:22:49:48:a5
192.168.001.004 - ap-tplinkeap615l                          d8:44:89:27:a7:ee  Open Ports: 80 (HTTP), 443 (HTTPS)
192.168.001.005 - pl-tplinkwpa7510g                         ac:84:c6:1a:6b:74  Open Ports: 80 (HTTP)
192.168.001.006 - ap-tplinkeap225b                          ac:84:c6:27:ee:2a  Open Ports: 80 (HTTP), 443 (HTTPS)
192.168.001.007 - ap-tplinkeap115b                          68:ff:7b:96:f0:05  Open Ports: 80 (HTTP), 443 (HTTPS)
192.168.001.008 - ap-tplinkeap615g                          60:83:e7:31:f0:a0  Open Ports: 80 (HTTP), 443 (HTTPS)
192.168.001.009 - devolo-5400                               8e:fc:a6:10:02:58  Open Ports: 80 (HTTP), 443 (HTTPS)
192.168.001.010 - sw-netgeargs116eb                         38:94:ed:2f:03:af  Open Ports: 80 (HTTP)
192.168.001.011 - sw-netgeargs308eppb                       54:07:7d:18:bf:c0  Open Ports: 80 (HTTP)
192.168.001.012 - sw-netgeargs308eppg                       54:07:7d:18:bf:41  Open Ports: 80 (HTTP)
192.168.001.013 - sw-netgeargs305eppk                       e0:46:ee:fc:da:d9  Open Ports: 80 (HTTP)
192.168.001.016 - storage1                                  00:11:32:62:77:39  Open Ports: 80 (HTTP), 139 (NETBIOS Session Service), 443 (HTTPS), 445 (Microsoft-DS), 515 (spooler), 554 (RTSP), 631 (IPP)
192.168.001.017 - storage2                                  00:11:32:20:55:af  Open Ports: 22 (SSH), 21 (FTP [Control]), 80 (HTTP), 139 (NETBIOS Session Service), 161 (SNMP), 443 (HTTPS), 445 (Microsoft-DS)
192.168.001.036 - esp32-alarm                               9c:9c:1f:e9:d2:28  Open Ports: 80 (HTTP)
192.168.001.037 - shelly1pm-borrelbol                       08:3a:f2:02:09:3c
192.168.001.039 - volumio-keuken                            b8:27:eb:e0:5b:c5  Open Ports: 22 (SSH), 80 (HTTP), 111 (SUN Remote Procedure Call), 139 (NETBIOS Session Service), 445 (Microsoft-DS)
...

IP inventory
------------
192.168.001.001 - router                                    00:11:32:bf:d2:75  Open Ports: 22 (SSH), 53 (DNS), 80 (HTTP), 139 (NETBIOS Session Service), 161 (SNMP), 445 (Microsoft-DS), 443 (HTTPS), 515 (spooler)
192.168.001.002 - ap-tpwr802n-engrie4                       78:8c:b5:d3:de:5d
192.168.001.003 - ap-tpwr802n-lepouttre343                  9c:53:22:49:48:a5
192.168.001.004 - ap-tplinkeap615l                          d8:44:89:27:a7:ee  Open Ports: 80 (HTTP), 443 (HTTPS)
192.168.001.005 - pl-tplinkwpa7510g                         ac:84:c6:1a:6b:74  Open Ports: 80 (HTTP)
192.168.001.006 - ap-tplinkeap225b                          ac:84:c6:27:ee:2a  Open Ports: 80 (HTTP), 443 (HTTPS)
192.168.001.007 - ap-tplinkeap115b                          68:ff:7b:96:f0:05  Open Ports: 80 (HTTP), 443 (HTTPS)
192.168.001.008 - ap-tplinkeap615g                          60:83:e7:31:f0:a0  Open Ports: 80 (HTTP), 443 (HTTPS)
192.168.001.009 - devolo-5400                               8e:fc:a6:10:02:58  Open Ports: 80 (HTTP), 443 (HTTPS)
192.168.001.010 - sw-netgeargs116eb                         38:94:ed:2f:03:af  Open Ports: 80 (HTTP)
192.168.001.011 - sw-netgeargs308eppb                       54:07:7d:18:bf:c0  Open Ports: 80 (HTTP)
192.168.001.012 - sw-netgeargs308eppg                       54:07:7d:18:bf:41  Open Ports: 80 (HTTP)
192.168.001.013 - sw-netgeargs305eppk                       e0:46:ee:fc:da:d9  Open Ports: 80 (HTTP)
192.168.001.014
192.168.001.015
192.168.001.016 - storage1                                  00:11:32:62:77:39  Open Ports: 80 (HTTP), 139 (NETBIOS Session Service), 443 (HTTPS), 445 (Microsoft-DS), 515 (spooler), 554 (RTSP), 631 (IPP)
192.168.001.017 - storage2                                  00:11:32:20:55:af  Open Ports: 22 (SSH), 21 (FTP [Control]), 80 (HTTP), 139 (NETBIOS Session Service), 161 (SNMP), 443 (HTTPS), 445 (Microsoft-DS)
192.168.001.018
...
~~~

Extract from a sample .mdns file
~~~
##################################################
### File created by Scan-Network               ###
###                 Version: 4.00              ###
### File created on 2025-08-23                 ###
##################################################
### Network: 192.168.1       255.255.255.0     ###
###          192.168.1.0/24                    ###
###          192.168.1.0     255.255.255.0     ###
##################################################

Hosts broadcasting services
---------------------------
192.168.001.001 - router                                    Port:  8000 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
                                                            Port:     9 - Service: WORKSTATION                              (_workstation._tcp.local. )
192.168.001.009 - devolo-5400                               Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
192.168.001.017 - storage2                                  Port:     0 - Service: DEVICE INFO                              (_device-info._tcp.local. )
                                                            Port:    21 - Service: FTP                                      (_ftp._tcp.local.         )
                                                            Port:   445 - Service: SMB                                      (_smb._tcp.local.         )
192.168.001.036 - esp32-alarm                               Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
                                                            Port:  3232 - Service: OTA                                      (_arduino._tcp.local.     ) with properties: auth_upload: no, ssh_upload: no, tcp_check: no, board: doitESP32devkitV1
192.168.001.037 - shelly1pm-borrelbol                       Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
                                                            Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
192.168.001.039 - volumio-keuken                            Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
                                                            Port:  5000 - Service: RAOP (REMOTE AUDIO OUTPUT PROTOCOL)      (_raop._tcp.local.        )
192.168.001.049 - volumio-living                            Port:     0 - Service: DEVICE INFO                              (_device-info._tcp.local. )
                                                            Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
                                                            Port:  5000 - Service: RAOP (REMOTE AUDIO OUTPUT PROTOCOL)      (_raop._tcp.local.        )
                                                            Port:   445 - Service: SMB                                      (_smb._tcp.local.         )
192.168.001.050 - volumio-garage                            Port:     0 - Service: DEVICE INFO                              (_device-info._tcp.local. )
                                                            Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
                                                            Port:  5000 - Service: RAOP (REMOTE AUDIO OUTPUT PROTOCOL)      (_raop._tcp.local.        )
                                                            Port:   445 - Service: SMB                                      (_smb._tcp.local.         )
192.168.001.057 - esp32-co2-48e7299ff6ec                    Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
                                                            Port:  3232 - Service: OTA                                      (_arduino._tcp.local.     ) with properties: auth_upload: no, ssh_upload: no, tcp_check: no, board: doitESP32devkitV1
192.168.001.059 - shelly25-office                           Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
192.168.001.061 - chromecast-bedroom                        Port:  8009 - Service: CHROMECAST                               (_googlecast._tcp.local.  )
192.168.001.064 - shellyplug-badkamer                       Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
192.168.001.069 - shelly25-keuken                           Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
192.168.001.070 - epsonwf3820                               Port:    80 - Service: HTTP WEB SERVER                          (_http._tcp.local.        )
                                                            Port:   631 - Service: PRINTER                                  (_ipp._tcp.local.         )
...


Services being broadcasted
--------------------------
Service: CHROMECAST                               (_googlecast._tcp.local.)
  chromecast-bedroom                       on <192.168.001.061> listing on port <8009>

Service: DEVICE INFO                              (_device-info._tcp.local.)
  storage2                                 on <192.168.001.017> listing on port <0>
  volumio-garage                           on <192.168.001.050> listing on port <0>
  volumio-badkamer                         on <192.168.001.083> listing on port <0>
  volumio-living                           on <192.168.001.049> listing on port <0>

Service: ESPHOME                                  (_esphomelib._tcp.local.)
  esp32-bt-proxy                           on <192.168.001.143> listing on port <6053>

Service: FTP                                      (_ftp._tcp.local.)
  storage2                                 on <192.168.001.017> listing on port <21>

Service: HTTP WEB SERVER                          (_http._tcp.local.)
  shellyplug-bedverwarming                 on <192.168.001.077> listing on port <80>
  shelly25-office                          on <192.168.001.059> listing on port <80>
  shelly25-regenwater                      on <192.168.001.122> listing on port <80>
  shelly25-borrelsteen                     on <192.168.001.139> listing on port <80>
  shellyplug-badkamer                      on <192.168.001.064> listing on port <80>
  shellyplug-badkamer2                     on <192.168.001.126> listing on port <80>
...
~~~


<img width="1920" height="1152" alt="image" src="https://github.com/user-attachments/assets/7b2a377d-f0e2-48f9-80f4-f11b206ea15a" />

