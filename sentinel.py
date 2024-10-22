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
RawDisplay        = None
PacketTypeDisplay = None


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
    return None


def get_vendor(mac):
    mac = mac.upper()  # Ensure MAC is uppercase for consistency
    if mac in vendor_cache:
        return vendor_cache[mac]
    try:
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
            vendor = 'Unknown or Malformed MAC Address'
    
    vendor_cache[mac] = vendor
    return vendor




def packet_callback(packet):
    global PacketTypeDisplay
    global RawDisplay

    #RawDisplay.Clear()
    #RawDisplay.ScrollPrint(get_raw_packet_string(packet))
    RawDisplay.ScrollPrint('---------------------------------------------------')

    packet_layers = identify_packet_layers(packet)
    for layer in packet_layers:
      RawDisplay.ScrollPrint(layer)
      


    #packet_details_string = get_packet_details_as_string(packet)
    #RawDisplay.ScrollPrint(packet_details_string)
    #packet_info = packet.show(dump=True)
    #RawDisplay.ScrollPrint(packet_info)  # Now the packet details are captured in a string

    #RawDisplay.ScrollPrint(analyze_packet(packet))
    #time.sleep(2)
    try:
        source_mac = get_source_mac(packet)
        if not source_mac:
            PacketTypeDisplay.ScrollPrint(format_packet(packet))
            return

        vendor = get_vendor(source_mac)

        if packet.haslayer(DHCP):
            PacketTypeDisplay.ScrollPrint(f"DHCP Packet (likely phone) from MAC: {source_mac} Vendor: {vendor}")
            #log_packet(source_mac, vendor, "DHCP")
        
        elif packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP request
            PacketTypeDisplay.ScrollPrint(f"ARP Packet (likely phone) from MAC: {source_mac} Vendor: {vendor}")
            #log_packet(source_mac, vendor, "ARP")
        
        elif packet.haslayer(Dot11ProbeReq):
            ssid = packet[Dot11ProbeReq].info.decode('utf-8', errors='ignore') if packet[Dot11ProbeReq].info else 'Hidden/Unknown SSID'
            PacketTypeDisplay.ScrollPrint(f"Packet from MAC: {source_mac}, Vendor: {vendor}, SSID: {ssid}")
            #log_packet(source_mac, vendor, "ProbeReq", ssid)
    

        else:
            # General packet handling
            PacketTypeDisplay.ScrollPrint(format_packet(packet))
    except Exception as e:
        PrintLine = f"Error parsing packet: {e}"
        RawDisplay.ScrollPrint(PrintLine)



#def log_packet(source_mac, vendor, packet_type, ssid=None):
#    with open("packet_log.csv", "a") as log_file:
#        log_writer = csv.writer(log_file)
#        # Use datetime.now() from datetime module to get current timestamp
#        log_writer.writerow([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source_mac, vendor, packet_type, ssid])








def sniff_packets(interface):
    """
    Sniffs packets on the given interface.
    :param interface: Name of the Wi-Fi interface in monitor mode
    """
    global PacketTypeDisplay
    global RawDisplay


    try:
        RawDisplay.ScrollPrint(PrintLine='Sniffing Packets')
        # Sniff packets continuously and send them to packet_callback for processing
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        RawDisplay.ScrollPrint(PrintLine='Stopping...')
    except Exception as e:
        RawDisplay.ScrollPrint(PrintLine='ERROR - ')
        RawDisplay.ScrollPrint(PrintLine=e)


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
    global RawDisplay
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
        RawDisplay.ScrollPrint(f"Packet Type: {packet_details['type']}")
        for key, value in packet_details['fields'].items():
            RawDisplay.ScrollPrint(f"{key}: {value}")

    except Exception as e:
        RawDisplay.ScrollPrint(f"Error analyzing packet: {e}")
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
        layers.append("Unknown Packet Type")

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
packet = sniff(count=1)[0]  # Sniff one packet for demonstration purposes
print(identify_packet_type(packet))







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
    global RawDisplay
    global PacketTypeDisplay

    looping = True

    # Call the helper function to initialize curses
    textwindows.initialize_curses(stdscr)


    #Calculate window sizes for two equal windows
    max_y, max_x = stdscr.getmaxyx()
    window_width = max_x // 2

    #Create display windows
    PacketTypeDisplay = textwindows.TextWindow('PacketTypeDisplay', rows=max_y - 1, columns=window_width, y1=0, x1=0, ShowBorder='Y', BorderColor=2, TitleColor=3)
    PacketTypeDisplay.ScrollPrint("Packet Types go here")
    
    RawDisplay        = textwindows.TextWindow('RawDisplay', rows=max_y - 1, columns=window_width, y1=0, x1=window_width +1, ShowBorder='Y', BorderColor=2, TitleColor=3)
    RawDisplay.ScrollPrint("Raw Packet Data")


    RawDisplay.refresh()
    PacketTypeDisplay.refresh()


    # Example usage
    interface = get_monitor_mode_interface()
    
    # Refresh initial windows


    sniff_packets(interface)
    RawDisplay.refresh()
    PacketTypeDisplay.refresh()


  
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




