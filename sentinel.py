# October

import curses
import textwindows
import time
import os
from datetime import datetime  # Import only what's needed for clarity
import csv

import netaddr
from scapy.all import *
from scapy.layers.dhcp import DHCP
from scapy.layers.l2 import ARP
from scapy.layers.dot11 import Dot11


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

import netaddr
import datetime
import csv
from scapy.layers.dot11 import Dot11, Dot11ProbeReq
from scapy.layers.dhcp import DHCP
from scapy.layers.l2 import ARP, Ether

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




def get_vendor(mac):
    if mac in vendor_cache:
        return vendor_cache[mac]
    try:
        MAC = netaddr.EUI(mac)
        vendor = MAC.oui.registration().org
    except netaddr.core.NotRegisteredError:
        # Convert MAC to string to handle checking for randomized addresses
        mac_str = str(MAC).lower()
        first_octet = mac_str.split(":")[0]
        
        try:
            # Attempt to convert the first octet to an integer with base 16
            if int(first_octet, 16) & 0x02:
                vendor = 'Randomized MAC Address'
            else:
                vendor = 'Unknown or Not Registered'
        except ValueError:
            # Handle the case where the first octet is not a valid hex number
            vendor = 'Unknown or Malformed MAC Address'
    
    # Cache the vendor for future lookups
    vendor_cache[mac] = vendor
    return vendor






def get_source_mac(packet):
    if packet.haslayer(Ether):
        return packet[Ether].src
    elif packet.haslayer(ARP):
        return packet[ARP].hwsrc
    elif packet.haslayer(Dot11):
        return packet[Dot11].addr2
    return None




def packet_callback(packet):
    global PacketTypeDisplay
    global RawDisplay

    RawDisplay.ScrollPrint(get_raw_packet_string(packet))


    try:
        source_mac = get_source_mac(packet)
        if not source_mac:
            PacketTypeDisplay.ScrollPrint(format_packet(packet))
            return

        vendor = get_vendor(source_mac)

        if packet.haslayer(DHCP):
            PacketTypeDisplay.ScrollPrint(f"DHCP Packet (likely phone) from MAC: {source_mac} Vendor: {vendor}")
            log_packet(source_mac, vendor, "DHCP")
        
        elif packet.haslayer(ARP) and packet[ARP].op == 1:  # ARP request
            PacketTypeDisplay.ScrollPrint(f"ARP Packet (likely phone) from MAC: {source_mac} Vendor: {vendor}")
            log_packet(source_mac, vendor, "ARP")
        
        elif packet.haslayer(Dot11ProbeReq):
            ssid = packet[Dot11ProbeReq].info.decode('utf-8', errors='ignore') if packet[Dot11ProbeReq].info else 'Hidden/Unknown SSID'
            PacketTypeDisplay.ScrollPrint(f"Packet from MAC: {source_mac}, Vendor: {vendor}, SSID: {ssid}")
            log_packet(source_mac, vendor, "ProbeReq", ssid)
    

        else:
            # General packet handling
            PacketTypeDisplay.ScrollPrint(format_packet(packet))
    except Exception as e:
        PrintLine = f"Error parsing packet: {e}"
        RawDisplay.ScrollPrint(PrintLine)

def log_packet(source_mac, vendor, packet_type, ssid=None):
    with open("packet_log.csv", "a") as log_file:
        log_writer = csv.writer(log_file)
        # Use datetime.now() from datetime module to get current timestamp
        log_writer.writerow([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source_mac, vendor, packet_type, ssid])








def sniff_packets(interface):
    """
    Sniffs packets on the given interface.
    :param interface: Name of the Wi-Fi interface in monitor mode
    """
    global PacketTypeDisplay
    global RawDisplay


    try:
        RawDisplay.ScrollPrint(PrintLine='Starting...')
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


    time.sleep(1)

    interface = "wlan0"  # Replace with your Wi-Fi dongle's interface name


    # Refresh initial windows
 
    while looping:
        # Check for key press
        key = stdscr.getch()
        if key != curses.ERR:
            looping = False
            break

        # Update both windows with scrolling text
        sniff_packets(interface)
        RawDisplay.refresh()
        PacketTypeDisplay.referesh()


        # Increment counter and add delay
        time.sleep(0.1)
       


#Call main
curses.wrapper(main)




