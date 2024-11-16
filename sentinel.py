

# October

import curses
import textwindows
import time
import os
from datetime import datetime  # Import only what's needed for clarity
import csv
import subprocess
import re

import netaddr

from scapy.all import *
from scapy.layers.l2 import Dot3, Dot1Q, Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dhcp import DHCP
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp


#Global Variables
InfoWindow    = None
PacketWindow  = None
DetailsWindow = None


#--------------------------------------------------------------------
#   __  __    _    ___ _   _                                       --
#  |  \/  |  / \  |_ _| \ | |                                      --
#  | |\/| | / _ \  | ||  \| |                                      --
#  | |  | |/ ___ \ | || |\  |                                      --
#  |_|  |_/_/   \_\___|_| \_|                                      --
#                                                                  --
#  ____  ____   ___   ____ _____ ____ ____ ___ _   _  ____         --
# |  _ \|  _ \ / _ \ / ___| ____/ ___/ ___|_ _| \ | |/ ___|        --
# | |_) | |_) | | | | |   |  _| \___ \___ \| ||  \| | |  _         --
# |  __/|  _ <| |_| | |___| |___ ___) |__) | || |\  | |_| |        --
# |_|   |_| \_\\___/ \____|_____|____/____/___|_| \_|\____|        --
#                                                                  --
#--------------------------------------------------------------------

os.system('clear') #clear the terminal (optional)
os.system("figlet 'SENTINEL PASSIVE SURVEILLANCE SYSTEM'")


vendor_cache = {}


class PacketInfo:
    def __init__(self, mac=None, ip=None, signal=None, hardware_type=None, vendor=None, ssid=None, bssid=None,
                 protocol=None, src_port=None, dst_port=None, timestamp=None):
        # Specific fields
        self.mac           = mac  # MAC address of the packet source
        self.ip            = ip  # IP address of the packet source
        self.signal        = signal  # Signal strength
        self.hardware_type = hardware_type  # Hardware type (if ARP packet)
        self.vendor    = vendor  # MAC vendor info
        self.ssid      = ssid  # SSID for Wi-Fi packets
        self.bssid     = bssid  # BSSID for Wi-Fi packets
        self.protocol  = protocol  # Protocol used in the packet (e.g., TCP, UDP)
        self.src_port  = src_port  # Source port for TCP/UDP packets
        self.dst_port  = dst_port  # Destination port for TCP/UDP packets
        self.timestamp = timestamp  # Timestamp when packet was captured

        # Generic key-value fields for flexibility
        self.generic_fields = {}

    def update_from_packet(self, packet):
        """Update the fields based on the given packet."""
        self.timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

        # Extract MAC Address and Vendor Info
        if packet.haslayer(Dot11):
            self.mac = packet.addr2
            self.bssid = packet.addr3 if hasattr(packet, 'addr3') else None
            self.ssid = packet.info.decode() if hasattr(packet, 'info') and isinstance(packet.info, bytes) else None
            self.vendor = self.get_vendor_info(self.mac) if self.mac else None

        # Extract IP Information
        if packet.haslayer(IP):
            self.ip = packet[IP].src
            self.protocol = packet[IP].proto

        # Extract TCP/UDP Ports
        if packet.haslayer("TCP") or packet.haslayer("UDP"):
            self.src_port = packet.sport
            self.dst_port = packet.dport

        # Extract Signal Strength
        if packet.haslayer(Dot11) and hasattr(packet, 'dBm_AntSignal'):
            self.signal = packet.dBm_AntSignal

        # Extract Hardware Type (if ARP packet)
        if packet.haslayer(ARP):
            self.hardware_type = packet.hwtype

        # Store custom fields from the packet for anything additional
        self.generic_fields['summary'] = packet.summary()

    @staticmethod
    def get_vendor_info(mac):
        # Placeholder: Use mac-vendor-lookup or another database/API for real lookup
        return "Unknown Vendor"

    def set_generic_field(self, key, value):
        """Set a generic key-value field for any additional info."""
        self.generic_fields[key] = value

    def get_generic_field(self, key):
        """Get the value of a generic key-value field."""
        return self.generic_fields.get(key, None)

    def __str__(self):
        """Formatted output for displaying packet information."""
        return (f"Timestamp: {self.timestamp}\n"
                f"MAC: {self.mac}\n"
                f"Vendor: {self.vendor}\n"
                f"IP: {self.ip}\n"
                f"Signal: {self.signal}\n"
                f"Hardware Type: {self.hardware_type}\n"
                f"SSID: {self.ssid}\n"
                f"BSSID: {self.bssid}\n"
                f"Protocol: {self.protocol}\n"
                f"Source Port: {self.src_port}\n"
                f"Destination Port: {self.dst_port}\n"
                f"Generic Fields: {self.generic_fields}\n")






def get_raw_packet_string(packet):
    """
    Returns the raw packet details as a formatted string.
    Uses Scapy's built-in show() method with dump=True to capture the packet details.
    
    :param packet: The packet to be formatted.
    :return: A string containing the raw packet details.
    """
    if packet:
        raw_packet_str = packet.show(dump=True)  # Capture the output of packet.show() as a string
        return raw_packet_str
    return "No packet data available"




def print_raw_packet(packet):
    """
    Prints the raw packet in a pretty formatted way.
    Uses Scapy's built-in show() method to display all packet layers and details.
    
    :param packet: The packet to be displayed.
    """
    if packet:
        print("\n" + "="*40)
        print("Raw Packet Details:")
        print("="*40)
        packet.show()  # This uses Scapy's built-in function to pretty print the packet details
        print("="*40 + "\n")




def get_source_mac(packet):
    def get_mac_field(field):
        return field.upper() if isinstance(field, str) else field

    if packet.haslayer(Ether):
        return get_mac_field(packet[Ether].src)
    elif packet.haslayer(ARP):
        return get_mac_field(packet[ARP].hwsrc)
    elif packet.haslayer(Dot11):
        return get_mac_field(packet[Dot11].addr2)
    elif packet.haslayer(Dot1Q):
        return get_mac_field(packet[Dot1Q].src)  # VLAN Tagged Frame
    elif packet.haslayer(Dot3):
        return get_mac_field(packet[Dot3].src)  # For LLC packets over Ethernet
    return 'No Source MAC'


def get_vendor(mac):

    if mac == None:
        return 'No Vendor'

    try:
        mac = mac.upper()  # Ensure MAC is uppercase for consistency
        if mac in vendor_cache:
          return vendor_cache[mac]
        MAC = netaddr.EUI(mac)
        vendor = MAC.oui.registration().org
    except netaddr.core.NotRegisteredError:
        mac_str = str(MAC).upper()
        first_octet = mac_str.split(":")[0]
        
        try:
            if int(first_octet, 16) & 0x02:
                vendor = 'Randomized MAC Address'
            else:
                vendor = 'Unknown or Not Registered'
        except ValueError:
            vendor = 'Unknown'
    
    vendor_cache[mac] = vendor
    return vendor




def packet_callback(packet):
    global PacketWindow
    global InfoWindow
    global DetailsWindow

    #InfoWindow.Clear()
    #InfoWindow.ScrollPrint(get_raw_packet_string(packet))


    PacketType = identify_packet_type(packet)


    PacketWindow.ScrollPrint('---------------------------------------------------')
    PacketWindow.ScrollPrint('PacketType: ' + PacketType)


    InfoWindow.ScrollPrint('---------------------------------------------------')
    packet_info = packet.show(dump=True)
    InfoWindow.ScrollPrint(packet_info)  # Now the packet details are captured in a string

    
    """ I'm only seeing one layer, and it is the same name as the packet.  
    packet_layers = identify_packet_layers(packet)
    for layer in packet_layers:
      count = count + 1
      PacketWindow.ScrollPrint(f'{count}     Layer: ' + layer)
      PacketWindow.ScrollPrint('')
    """  


    #packet_details_string = get_packet_details_as_string(packet)
    #InfoWindow.ScrollPrint(packet_details_string)
    
    #InfoWindow.ScrollPrint(analyze_packet(packet))
    #time.sleep(2)
    try:
        source_mac = get_source_mac(packet)
        vendor     = get_vendor(source_mac)

        PacketWindow.ScrollPrint('source_mac: ' + str(source_mac))
        PacketWindow.ScrollPrint('    vendor: ' + str(vendor))


        if packet.haslayer(DHCP):
            PacketWindow.ScrollPrint(f"DHCP Packet (likely phone) from MAC: {source_mac} Vendor: {vendor}")
            #log_packet(source_mac, vendor, "DHCP")
        
        if packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP request
            PacketWindow.ScrollPrint(f"ARP Packet (likely phone) from MAC: {source_mac} Vendor: {vendor}")
            #log_packet(source_mac, vendor, "ARP")
        
        if packet.haslayer(Dot11ProbeReq):
            ssid = packet[Dot11ProbeReq].info.decode('utf-8', errors='ignore') if packet[Dot11ProbeReq].info else 'Hidden/Unknown SSID'
            PacketWindow.ScrollPrint(f"Probe Request Packet from MAC: {source_mac}, Vendor: {vendor}, SSID: {ssid}")
            #log_packet(source_mac, vendor, "ProbeReq", ssid)
    

        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Beacon].info.decode('utf-8', errors='ignore') if packet[Dot11Beacon].info else 'Hidden/Unknown SSID'
            PacketWindow.ScrollPrint(f"BeaCON Packet from MAC: {source_mac}, Vendor: {vendor}, SSID: {ssid}")
            
            
          

        packet_details = extract_packet_info(packet)
        DetailsWindow.ScrollPrint('--------------------------------------------')
        DetailsWindow.ScrollPrint(packet_details)
        DetailsWindow.ScrollPrint('--------------------------------------------')
            


    except Exception as ErrorMessage:
        TraceMessage   = traceback.format_exc()
        AdditionalInfo = f"Processing Packet: {format_packet(packet)}"
        InfoWindow.ScrollPrint(PrintLine='ERROR - ')
        InfoWindow.ScrollPrint(PrintLine=ErrorMessage)
        InfoWindow.ErrorHandler(ErrorMessage,TraceMessage,AdditionalInfo)
        InfoWindow.ScrollPrint(f"Error parsing packet: {ErrorMessage}")

    time.sleep(2)


#def log_packet(source_mac, vendor, packet_type, ssid=None):
#    with open("packet_log.csv", "a") as log_file:
#        log_writer = csv.writer(log_file)
#        # Use datetime.now() from datetime module to get current timestamp
#        log_writer.writerow([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source_mac, vendor, packet_type, ssid])









def extract_packet_info(packet):
    """
    Extracts as much information as possible from a given packet.
    """
    packet_details = []

    try:
        # Get a raw string representation of the packet layers
        packet_raw_info = packet.show(dump=True)
        packet_details.append(packet_raw_info)

        # Iterate over each layer in the packet to extract as much info as possible
        layers = []
        count = 0

        while True:
            layer = packet.getlayer(count)
            if layer is None:
                break
            layers.append(layer)
            count += 1

        # Loop through each layer and extract relevant fields
        for layer in layers:
            layer_name = layer.__class__.__name__
            packet_details.append(f"Layer {count}: {layer_name}")
            fields = layer.fields
            for field_name, field_value in fields.items():
                packet_details.append(f"    {field_name}: {field_value}")

            packet_details.append('')  # Add a blank line between layers

    except Exception as e:
        packet_details.append(f"Error extracting packet details: {str(e)}")

    return "\n".join(packet_details)












def sniff_packets(interface):
    """
    Sniffs packets on the given interface.
    :param interface: Name of the Wi-Fi interface in monitor mode
    """
    global PacketWindow
    global InfoWindow
    global DetailsWindow
        

    try:
        InfoWindow.ScrollPrint(PrintLine='Sniffing Packets')
        # Sniff packets continuously and send them to packet_callback for processing
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        InfoWindow.ScrollPrint(PrintLine='Stopping...')
    except Exception as ErrorMessage:
        TraceMessage   = traceback.format_exc()
        InfoWindow.ErrorHandler(ErrorMessage,TraceMessage,'')


def format_packet(packet):
    """
    Formats a packet for output as a string.
    :param packet: Packet to format
    :return: Formatted string representation of the packet
    """
    try:
        summary = packet.summary()
        if packet.haslayer(Dot11):
            source_mac = packet[Dot11].addr2 or "Unknown"
            dest_mac = packet[Dot11].addr1 or "Unknown"
            formatted_string = f"[Source: {source_mac:<17}] [Destination: {dest_mac:<17}] - {summary}"
        else:
            formatted_string = summary
        return formatted_string.expandtabs(4)
    except Exception as e:
        return f"Error formatting packet: {e}"






def analyze_packet(packet):
    """
    Analyze any packet to determine its type and extract relevant information.
    :param packet: The packet to analyze (Scapy packet object)
    """
    global InfoWindow
    try:
        # Initialize a dictionary to store packet details
        packet_details = {
            'type': None,
            'fields': {}
        }

        # Determine the type of packet and extract fields accordingly
        if packet.haslayer(Dot11):
            packet_details['type'] = '802.11 Wireless'
            dot11 = packet.getlayer(Dot11)
            packet_details['fields'] = {
                'Source MAC': dot11.addr2 if dot11.addr2 else 'Unknown',
                'Destination MAC': dot11.addr1 if dot11.addr1 else 'Unknown',
                'BSSID': dot11.addr3 if dot11.addr3 else 'Unknown',
                'Type': dot11.type,
                'Subtype': dot11.subtype
            }

            # Handle Beacon and Probe Request frames specifically
            if packet.haslayer(Dot11Beacon):
                beacon = packet.getlayer(Dot11Beacon)
                ssid = packet[Dot11Elt].info.decode('utf-8', 'ignore') if packet.haslayer(Dot11Elt) else 'Hidden'
                packet_details['fields'].update({
                    'SSID': ssid,
                    'Beacon Interval': beacon.beacon_interval,
                    'Capabilities': beacon.cap
                })

            elif packet.haslayer(Dot11ProbeReq):
                ssid = packet[Dot11Elt].info.decode('utf-8', 'ignore') if packet.haslayer(Dot11Elt) else 'Unknown'
                packet_details['fields'].update({
                    'SSID': ssid
                })

        elif packet.haslayer(ARP):
            packet_details['type'] = 'ARP'
            arp = packet.getlayer(ARP)
            packet_details['fields'] = {
                'Operation': arp.op,  # ARP request (1) or reply (2)
                'Source MAC': arp.hwsrc,
                'Source IP': arp.psrc,
                'Destination MAC': arp.hwdst,
                'Destination IP': arp.pdst
            }

        elif packet.haslayer(IP):
            packet_details['type'] = 'IP'
            ip = packet.getlayer(IP)
            packet_details['fields'] = {
                'Source IP': ip.src,
                'Destination IP': ip.dst,
                'Protocol': ip.proto,
                'TTL': ip.ttl
            }

            if packet.haslayer(TCP):
                tcp = packet.getlayer(TCP)
                packet_details['fields'].update({
                    'Source Port': tcp.sport,
                    'Destination Port': tcp.dport,
                    'Flags': tcp.flags
                })

            elif packet.haslayer(UDP):
                udp = packet.getlayer(UDP)
                packet_details['fields'].update({
                    'Source Port': udp.sport,
                    'Destination Port': udp.dport
                })

            elif packet.haslayer(ICMP):
                icmp = packet.getlayer(ICMP)
                packet_details['fields'].update({
                    'ICMP Type': icmp.type,
                    'ICMP Code': icmp.code
                })

        else:
            packet_details['type'] = 'Unknown'
            packet_details['fields'] = {'Raw Data': packet.summary()}

        # Format the packet details for display
        InfoWindow.ScrollPrint(f"Packet Type: {packet_details['type']}")
        for key, value in packet_details['fields'].items():
            InfoWindow.ScrollPrint(f"{key}: {value}")

    except Exception as e:
        InfoWindow.ScrollPrint(f"Error analyzing packet: {e}")
        traceback.print_exc()




def get_monitor_mode_interface():
    try:
        # Run 'iw dev' to get information about wireless interfaces
        result = subprocess.run(['iw', 'dev'], stdout=subprocess.PIPE, text=True)
        output = result.stdout

        # Regex to find interface name and mode
        interfaces = re.findall(r'Interface\s+(\w+)\n.*?type\s+(\w+)', output, re.DOTALL)

        # Check which interface is in monitor mode
        for iface, mode in interfaces:
            if mode == "monitor":
                return iface

    except subprocess.CalledProcessError as e:
        print(f"Error retrieving interface information: {e}")

    return None



def identify_packet_layers(packet):
    """
    Identifies all the layers present in the packet and returns a list of protocol names.

    :param packet: Scapy packet object to be analyzed.
    :return: A list of strings representing the identified layers.
    """
    layers = []

    # Check for common layers and append if they exist in the packet
    if packet.haslayer(DHCP):
        layers.append("DHCP Packet")
    if packet.haslayer(ARP):
        layers.append("ARP Packet")
    if packet.haslayer(Dot11):
        if packet.haslayer(Dot11Beacon):
            layers.append("802.11 Beacon Frame (Router/AP)")
        elif packet.haslayer(Dot11ProbeReq):
            layers.append("802.11 Probe Request (Mobile Device)")
        elif packet.haslayer(Dot11ProbeResp):
            layers.append("802.11 Probe Response")
        elif packet.haslayer(Dot11AssoReq):
            layers.append("802.11 Association Request")
        elif packet.haslayer(Dot11AssoResp):
            layers.append("802.11 Association Response")
        else:
            layers.append("802.11 Packet")
    if packet.haslayer(IP):
        layers.append("IP Packet")
        if packet.haslayer(TCP):
            layers.append("TCP Packet")
        elif packet.haslayer(UDP):
            layers.append("UDP Packet")
        elif packet.haslayer(ICMP):
            layers.append("ICMP Packet")
    if packet.haslayer(Dot3):
        layers.append("802.3 Ethernet Packet")
    if packet.haslayer(Dot1Q):
        layers.append("802.1Q VLAN Tagged Frame")

    # If no known layers found, append unknown
    if not layers:
        layers.append("Unknown Layer")

    return layers



def identify_packet_type(packet):
    """
    Identifies the type of packet and returns a string indicating the protocol.

    :param packet: Scapy packet object to be analyzed.
    :return: A string representing the identified packet type.
    """


    if packet.haslayer(DHCP):
        return "DHCP Packet"
    elif packet.haslayer(ARP):
        return "ARP Packet"
    elif packet.haslayer(Dot11):
        if packet.haslayer(Dot11Beacon):
            return "802.11 Beacon Frame (Router/AP)"
        elif packet.haslayer(Dot11ProbeReq):
            return "802.11 Probe Request (Mobile Device)"
        elif packet.haslayer(Dot11ProbeResp):
            return "802.11 Probe Response"
        elif packet.haslayer(Dot11AssoReq):
            return "802.11 Association Request"
        elif packet.haslayer(Dot11AssoResp):
            return "802.11 Association Response"
        else:
            return "802.11 Packet"
    elif packet.haslayer(IP):
        if packet.haslayer(TCP):
            return "TCP Packet"
        elif packet.haslayer(UDP):
            return "UDP Packet"
        elif packet.haslayer(ICMP):
            return "ICMP Packet"
        else:
            return "IP Packet"
    

    elif packet.haslayer(Dot3):
        return "802.3 Ethernet Packet"
    elif packet.haslayer(Dot1Q):
        return "802.1Q VLAN Tagged Frame"
    else:
        return "Unknown Packet Type"

# Example usage:
#packet = sniff(count=1)[0]  # Sniff one packet for demonstration purposes
#print(identify_packet_type(packet))







def get_packet_details_as_string(packet):
    """
    Extracts all information from a packet and returns it as a formatted string.
    
    :param packet: Scapy packet object to be analyzed.
    :return: A string containing detailed information about the packet.
    """
    packet_details = []

    # Iterate over each layer in the packet
    layer = packet
    while layer:
        # Add the layer name as a header
        packet_details.append(f"###[ {layer.name} ]###")

        # Extract all fields from the current layer
        for field_name, field_value in layer.fields.items():
            packet_details.append(f"{field_name:15}: {field_value}")

        # Move to the next layer
        layer = layer.payload

    # Combine all the details into a single formatted string
    formatted_packet_details = "\n".join(packet_details)

    return formatted_packet_details







###########################################################
#  MAIN PROCESSING                                        #
###########################################################


def main(stdscr):
    global PacketWindow
    global InfoWindow
    global DetailsWindow

    looping = True

    # Call the helper function to initialize curses
    textwindows.initialize_curses(stdscr)


    #Calculate window sizes for two equal windows
    max_y, max_x = stdscr.getmaxyx()
    window_width = max_x // 3

    #Create display windows
    PacketWindow = textwindows.TextWindow('PacketWindow',title='Packets', rows=max_y - 1, columns=window_width, y1=0, x1=0, ShowBorder='Y', BorderColor=2, TitleColor=3)
    PacketWindow.DisplayTitle()
    
    InfoWindow   = textwindows.TextWindow('InfoWindow', title='Information', rows=max_y - 1, columns=window_width, y1=0, x1=window_width +1, ShowBorder='Y', BorderColor=2, TitleColor=3)
    InfoWindow.ScrollPrint("Raw Packet Data")
    InfoWindow.DisplayTitle()

    DetailsWindow   = textwindows.TextWindow('DetailsWindow', title='Extra Info', rows=max_y - 1, columns=window_width, y1=0, x1=window_width *2 +1, ShowBorder='Y', BorderColor=2, TitleColor=3)
    DetailsWindow.ScrollPrint("Details")
    DetailsWindow.DisplayTitle()


    PacketWindow.refresh()
    InfoWindow.refresh()
    DetailsWindow.refresh()
    
    PacketWindow.DisplayTitle()
    InfoWindow.DisplayTitle()
    DetailsWindow.DisplayTitle()


    # Example usage
    interface = get_monitor_mode_interface()
    
    # Refresh initial windows


    sniff_packets(interface)
    InfoWindow.refresh()
    PacketWindow.refresh()
    DetailsWindow.refresh()


  
  #  while looping:
        # Check for key press
  #      key = stdscr.getch()
  #      if key != curses.ERR:
  #          looping = False
  #          break

        # Update both windows with scrolling text

        # Increment counter and add delay
        #time.sleep(0.1)
       


#Call main
curses.wrapper(main)




