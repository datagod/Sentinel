'''
Notes: Do not write to the windows from multiple threads as this will lead to strange artifacts


Sentinel Passive Surveillance System
====================================

Description:
------------
This program is a passive network surveillance system designed to capture network packets,
 extract detailed information such as MAC addresses, SSIDs, vendors, and protocols, 
 and display the information in separate text windows. 
 It utilizes scapy for packet sniffing and curses for displaying the information in a text-based UI. 
 Additionally, the system performs channel hopping to capture packets across multiple Wi-Fi channels.

Author: Bill (Datagod)
Creation Date: October 2024

Change Log:
-----------
Date            | Author         | Description
----------------|----------------|-----------------------------------------------------------
2024-11-21      | datagod        | Initial version of the program.


'''




import curses
import queue
import textwindows
import time
import os
import sqlite3
from datetime import datetime  # Import only what's needed for clarity
import csv
import subprocess
import re
import json
from collections import Counter

import netaddr
import threading

from scapy.all import *
from scapy.layers.l2 import Dot3, Dot1Q, Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dhcp import DHCP
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp

# Import the device type dictionary from the other file
from device_type_dict import device_type_dict


#Global Variables
oui_dict      = None
vendor_cache  = {}
write_lock    = threading.Lock()
hop_interval  = 1  # Interval in seconds between channel hops
current_channel_info    = {"channel": None, "band": None, "frequency": None}
displayed_packets_cache = {}
key_count               = 0
friendly_devices_dict   = None
PacketCount             = 0
PacketQueue             = queue.Queue()
DBQueue                 = queue.Queue()
FriendlyDeviceCount     = 0
PacketDB                = "packet.db"
DBConnection            = None
PacketsSavedToDBCount   = 0

#Windows variables
HeaderWindow  = None
InfoWindow    = None
PacketWindow  = None
DetailsWindow = None
HorizontalWindowCount = 4
HeaderHeight  = 15
HeaderWidth   = 80



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




class PacketInfo:
    def __init__(self, mac=None, ip=None, signal=None, hardware_type=None, vendor=None, ssid=None, bssid=None,
                 protocol=None, src_port=None, dst_port=None, timestamp=None):
        # Specific fields
        self.mac           = mac  # MAC address of the packet source
        self.ip            = ip  # IP address of the packet source
        self.signal        = signal  # Signal strength
        self.hardware_type = hardware_type  # Hardware type (if ARP packet)
        self.vendor        = vendor  # MAC vendor info
        self.ssid          = ssid  # SSID for Wi-Fi packets
        self.bssid         = bssid  # BSSID for Wi-Fi packets
        self.protocol      = protocol  # Protocol used in the packet (e.g., TCP, UDP)
        self.src_port      = src_port  # Source port for TCP/UDP packets
        self.dst_port      = dst_port  # Destination port for TCP/UDP packets
        self.timestamp     = timestamp  # Timestamp when packet was captured

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
        return normalize_mac(field) if isinstance(field, str) else 'UNKNOWN'

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


def get_destination_mac(packet):
    def get_mac_field(field):
        return field.upper().replace('-', ':')   if isinstance(field, str) else field

    if packet.haslayer(Ether):
        return get_mac_field(packet[Ether].dst).upper().replace('-', ':')
    elif packet.haslayer(ARP):
        return get_mac_field(packet[ARP].hwdst).upper().replace('-', ':')
    elif packet.haslayer(Dot11):
        return get_mac_field(packet[Dot11].addr1).upper().replace('-', ':')
    elif packet.haslayer(Dot1Q):
        return get_mac_field(packet[Dot1Q].dst).upper().replace('-', ':')  # VLAN Tagged Frame
    elif packet.haslayer(Dot3):
        return get_mac_field(packet[Dot3].dst).upper().replace('-', ':')  # For LLC packets over Ethernet
    return 'No Destination MAC'


def get_vendor(mac, oui_dict):
    # Extract the OUI prefix (first 8 characters)
    mac_prefix = normalize_mac(mac[:8])  # Normalize delimiter format
    InfoWindow.ScrollPrint(f"Looking up MAC Prefix: {mac_prefix}")

    # Check if the OUI prefix is already in the cache
    if mac_prefix in vendor_cache:
        InfoWindow.ScrollPrint(f"Cache Hit for {mac_prefix}")
        return vendor_cache[mac_prefix]

    # Lookup in the OUI dictionary
    if mac_prefix in oui_dict:
        vendor_info = oui_dict[mac_prefix]
        InfoWindow.ScrollPrint(f"Vendor Found: {vendor_info}")
    else:
        # Fallback: Use netaddr to try and fetch vendor info if not in oui_dict
        try:
            MAC = netaddr.EUI(mac)
            vendor_info = (MAC.oui.registration().org, "No Long Description Available")
            InfoWindow.ScrollPrint(f"Fallback Vendor Info from netaddr: {vendor_info}")
        except (netaddr.core.NotRegisteredError, ValueError):
            vendor_info = ("Unknown", "Unknown")
            InfoWindow.ScrollPrint(f"Vendor Not Found for {mac_prefix}")

    # Store the found result in the vendor_cache for future lookups
    vendor_cache[mac_prefix] = vendor_info
    return vendor_info





'''
    try:
        MAC = netaddr.EUI(mac)
        vendor = MAC.oui.registration().org
    except netaddr.core.NotRegisteredError:
        vendor = 'Unknown or Not Registered'
    except ValueError:
        vendor = 'Unknown'

    # Cache the OUI result
    vendor_cache[mac_prefix] = vendor
    return vendor
'''

def extract_ssid(packet):
    #Extracts SSID from a packet if present.
    try:
        if packet.haslayer(Dot11Elt) and isinstance(packet[Dot11Elt].info, bytes):
            return packet[Dot11Elt].info.decode('utf-8', errors='ignore')
    except Exception as e:
        return 'UNKNOWN'
    return 'UNKNOWN'



def load_friendly_devices_dict(filename):
    with open(filename, 'r') as json_file:
        return json.load(json_file)

def load_oui_dict_from_json(filename):
    with open(filename, 'r') as json_file:
        return json.load(json_file)



# Example Lookup Function
def lookup_vendor_by_mac(mac, oui_dict):
    ## Extract and normalize the OUI prefix from MAC address
    mac_prefix = normalize_mac(mac[:8])
    return oui_dict.get(mac_prefix, ("Unknown", "Unknown"))




def determine_device_type(oui):
  device_type = device_type_dict.get(oui, "UNKNOWN")
  return device_type 



def determine_device_type_with_packet(packet):
    """
    Determines the likely type of the device that sent the given packet.
    
    Device types are inferred based on packet behavior, known vendors, SSID, or
    specific network activity.
    
    :param packet: Scapy packet object to analyze.
    :return: String indicating the likely device type.
    """

    # Check for already known vendor information from your lookup
    if packet.haslayer(Dot11) and packet.addr2:
        mac = normalize_mac(packet.addr2)
        
        if mac[:8] in vendor_cache:
            vendor_info = vendor_cache[mac[:8]]
            vendor_name = vendor_info[0].lower() if isinstance(vendor_info, tuple) else vendor_info.lower()

            # Determine device type based on vendor name
            if any(keyword in vendor_name for keyword in ["samsung", "apple", "huawei", "oneplus", "xiaomi"]):
                return "Mobile Phone"
            elif any(keyword in vendor_name for keyword in ["cisco", "tplink", "netgear", "dlink"]):
                return "Router/Access Point"
            elif any(keyword in vendor_name for keyword in ["intel", "lenovo", "dell", "hp"]):
                return "Laptop/Computer"
            elif any(keyword in vendor_name for keyword in ["amazon", "google", "nest", "sonos", "smart"]):
                return "Smart Home Device (e.g., Amazon Echo, Google Home)"
            elif any(keyword in vendor_name for keyword in ["tplink", "philips", "hue", "ring", "wyze"]):
                return "IoT Device"
            else:
                return "Unknown (" + vendor_name.title() + ")"

    # Wi-Fi Routers/Access Points: Typically broadcast beacon frames or respond to probe requests
    if packet.haslayer(Dot11Beacon):
        return "Router/Access Point"

    # Mobile Phones: Look for probe requests or DHCP requests
    if packet.haslayer(DHCP):
        return "Mobile Phone (DHCP Request)"
    if packet.haslayer(Dot11ProbeReq):
        return "Mobile Phone (Probe Request)"

    # Laptops/Computers: Often open specific ports (e.g., TCP 80, 443 for web, SSH, etc.)
    if packet.haslayer(TCP):
        if packet[TCP].dport in [22, 80, 443]:
            return "Laptop/Computer"

    # Fallback to Unknown Device
    return "Unknown Device"










# Function to search for a MAC address
def search_friendly_devices(mac, friendly_devices):
    for device in friendly_devices:
        if device["MAC"] == mac:
            return {"FriendlyName": device["FriendlyName"], "Type": device["Type"], "Brand": device["Brand"]}
    return None  # Return None if MAC is not found





#-------------------------------
#-- Database Functions
#-------------------------------



def save_DB_Packet(DBPacket):
    """
    Insert packet information into the Packet table.

    :param packet_info: A dictionary containing packet details.
    :param db_path: Path to the SQLite database file.
    """
    global InfoWindow
    global DBConnection


    try:
        # Connect to the SQLite database
        #InfoWindow.ScrollPrint("Connection Open")
        cursor = DBConnection.cursor()


        # Define SQL statement to insert packet data
        insert_query = '''
        INSERT INTO Packet (
            FriendlyName, FriendlyType, PacketType, DeviceType, 
            SourceMAC, SourceVendor, DestMAC, DestVendor, 
            SSID, Band, Channel
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        '''

        # Execute the insert statement with provided packet information
        cursor.execute(insert_query, (
            DBPacket.get('FriendlyName'),
            DBPacket.get('FriendlyType'),
            DBPacket.get('PacketType'),
            DBPacket.get('DeviceType'),
            DBPacket.get('SourceMAC'),
            DBPacket.get('SourceVendor'),
            DBPacket.get('DestMAC'),
            DBPacket.get('DestVendor'),
            DBPacket.get('SSID'),
            DBPacket.get('Band'),
            DBPacket.get('Channel')
        ))

        # Commit the changes 
        DBConnection.commit()
        #InfoWindow.ScrollPrint("Connection Closed")

        
        #print("Packet data inserted successfully.")
    except sqlite3.Error as e:
        InfoWindow.ScrollPrint(f"SQLite error: {e}")
    #finally:
        # Ensure the connection is closed
        #conn.close()
        #print("Insert operation complete.")





#-------------------------------
#-- Packet Callback 
#-------------------------------

def packet_callback(packet):
    try:
        # Add packet to the queues for processing and saving by other threads
        PacketQueue.put(packet)
        
    except Exception as e:
        TraceMessage = traceback.format_exc()
        InfoWindow.ErrorHandler(str(e), TraceMessage, "**Error in packet callback**")


def process_PacketQueue():
    global InfoWindow

    
    while True:
        try:
            # Retrieve a packet from the queue (wait indefinitely if empty)
            packet = PacketQueue.get()

            process_packet(packet)

            # Signal that processing of this item is done
            PacketQueue.task_done()

        except Exception as e:
            TraceMessage = traceback.format_exc()
            InfoWindow.ErrorHandler(str(e), TraceMessage, "Error in packet processing thread")



def process_DBQueue():
    global InfoWindow
    global DBQueue
    global PacketsSavedToDBCount
    global PacketDB
    global DBConnection

    #Database connections
    DBConnection = sqlite3.connect(PacketDB)
    InfoWindow.ScrollPrint("Database connection established.")


    while True:
        try:
            # Retrieve a packet from the DBqueue (wait indefinitely if empty)
            DBpacket = DBQueue.get()
            #InfoWindow.ScrollPrint("Got a packet from the DBQueue")

            save_DB_Packet(DBpacket)
            PacketsSavedToDBCount = PacketsSavedToDBCount + 1
            # Signal that processing of this item is done
            DBQueue.task_done()

        except Exception as e:
            TraceMessage = traceback.format_exc()
            InfoWindow.ErrorHandler(str(e), TraceMessage, "Error in DBQueue processing thread")



#------------------------------------
#-- Process Packet and Display Info
#------------------------------------


def process_packet(packet):
    
    global HeaderWindow
    global PacketWindow
    global InfoWindow
    global DetailsWindow
    global oui_dict
    global friendly_devices_dict
    global current_channel_info
    global displayed_packets_cache
    global key_count
    global PacketCount
    global FriendlyDeviceCount
    global DBQueue
    global PacketsSavedToDBCount

    count         = 0
    PacketCount   = PacketCount + 1
    source_vendor = ''
    dest_vendor   = ''
    channel       = 0
    band          = 0
    timestamp     = datetime.now()
    KeyTime       = datetime.now().replace(second=0, microsecond=0)

    DeviceType    = ''
    source_mac    = 'UNKNOWN'
    dest_mac      = 'UNKNOWN'
    source_oui    = ''
    ssid          = ''
    FriendlyName  = ''
    FriendlyType  = ''
    FriendlyBrand = ''
    PacketKey     = None




    

    def resolve_mac(mac, resolver_function, packet):
        if 'UNKNOWN' in mac.upper():
            return resolver_function(packet)
        return mac


    #-------------------------------
    #-- Get all packet information
    #-------------------------------

    try:
      #Get all the information about the packet before displaying anything
      PacketType     = identify_packet_type(packet)
      packet_layers  = identify_packet_layers(packet)
        
      #Convert packet to a string for displaying
      packet_info    = packet.show(dump=True)
      packet_details = get_packet_details_as_string(packet)

    
      

      #There can be more than one source/destination depending on the type of packet
      #We will focus on WIFI packets for this project
      mac_details   = extract_oui_and_vendor_information(packet)

      
      # Iterate through each key-value pair in the mac_info dictionary
      #InfoWindow.ScrollPrint("-----MAC DETAILS-------------------------------")
      for mac_type, details in mac_details.items():
        #InfoWindow.ScrollPrint(f"MAC_TYPE: {mac_type} {details}:")
        
        if 'SOURCE' in mac_type.upper():
          source_mac = normalize_mac(details.get('MAC', 'UNKNOWN'))
        if 'DEST' in mac_type.upper():
          dest_mac = normalize_mac(details.get('MAC', 'UNKNOWN'))

        # Extract MAC address, OUI, and Vendor information
        oui    = details.get('OUI', 'UNKNOWN')
        vendor = details.get('Vendor', 'UNKNOWN')

        if "source" in mac_type:
          source_vendor = vendor
        if "dest" in mac_type:
          dest_vendor = vendor

      # Resolving MACs if they are still unknown
      source_mac = resolve_mac(source_mac, get_source_mac, packet)
      dest_mac   = resolve_mac(dest_mac, get_destination_mac, packet)

      # Extract OUI if source_mac is known
      if 'UNKNOWN' not in source_mac.upper():
          source_oui = source_mac[:8]

      for mac_type, details in mac_details.items():
        if 'source'.upper() in mac_type.upper():
          source_vendor = f"{details['Vendor']}"
        elif 'destination'.upper() in mac_type.upper():
          dest_vendor = f"{details['Vendor']}"

      ssid    = extract_ssid(packet)
      channel = current_channel_info['channel']
      band    = current_channel_info['band']
      
      #DetailsWindow.UpdateLine(0,1,f"Band: {band} Channel: {str(channel).ljust(5)}")
      
      #HeaderWindow.UpdateLine(1,1,f"Packets: {PacketCount}")



      # Step 1: Try to determine device type using source OUI if it's available
      if source_oui is not None:
          DeviceType = determine_device_type(source_oui)

      # Step 2: If device type is still unknown, try another method using the packet
      if DeviceType == 'UNKNOWN':
          DeviceType = determine_device_type_with_packet(packet)

      # Step 3: As a final fallback, if packet type suggests it's a mobile device, mark it as 'Mobile'
      if DeviceType == 'UNKNOWN' and 'MOBILE' in PacketType.upper():
          DeviceType = 'Mobile'

      # Create a unique key for the packet based on important fields
      packet_key = (source_mac, ssid, vendor, DeviceType)
     
    
    except Exception as ErrorMessage:
      TraceMessage   = traceback.format_exc()
      AdditionalInfo = f"Processing Packet: {format_packet(packet)}"
      InfoWindow.ScrollPrint(PrintLine='ERROR - ')
      InfoWindow.ScrollPrint(PrintLine=ErrorMessage)
      InfoWindow.ErrorHandler(ErrorMessage,TraceMessage,AdditionalInfo)
      InfoWindow.ScrollPrint(f"Error parsing packet: {ErrorMessage}")

    


    # Check if the packet information is already in the cache
    if packet_key not in displayed_packets_cache:
      #add to cache
      displayed_packets_cache[packet_key] = True
      key_count = key_count + 1
      #DetailsWindow.ScrollPrint(f"{key_count} - {packet_key}")


      #Check for friendly device
      result = search_friendly_devices(source_mac,friendly_devices_dict)
      if result:
        FriendlyDeviceCount = FriendlyDeviceCount +1
        FriendlyName = result['FriendlyName']
        FriendlyType = result['Type']
        FriendlyBrand = result['Brand']
        DetailsWindow.ScrollPrint(f"{key_count} - {FriendlyName} - {FriendlyType} - {FriendlyBrand} - {ssid}")

      else:
          PacketWindow.ScrollPrint('INTRUDER DETAILS',Color=1)
          DetailsWindow.ScrollPrint(f"{key_count} - {DeviceType} - {source_mac} - {source_vendor} - {ssid},",Color=3)
          PacketWindow.ScrollPrint(f'CaptureDate:   {timestamp}')
          if FriendlyName:
              PacketWindow.ScrollPrint(f'FriendlyName:  {FriendlyName}')    
              PacketWindow.ScrollPrint(f'FriendlyType:  {FriendlyType}')    
          
          
          PacketWindow.ScrollPrint(f'PacketType:    {PacketType}')
          PacketWindow.ScrollPrint(f'DeviceType:    {DeviceType}')
          PacketWindow.ScrollPrint(f'Source MAC:    {source_mac}')
          PacketWindow.ScrollPrint(f'Source Vendor: {source_vendor}')
          PacketWindow.ScrollPrint(f'Dest MAC:      {dest_mac}')
          PacketWindow.ScrollPrint(f'Dest Vendor:   {dest_vendor}')
          PacketWindow.ScrollPrint(f'SSID:          {ssid}')
          PacketWindow.ScrollPrint(f'Band:          {band}')
          PacketWindow.ScrollPrint(f'channel:       {channel}')
          PacketWindow.ScrollPrint('---------------------------------------------------')

    
          #--------------------------------------
          #-- Save processed packet to DB Queue
          #--------------------------------------
          # For now we save Intruder details to the database
          DBPacket = {
            'CaptureDate' : timestamp,
            'FriendlyName': FriendlyName,
            'FriendlyType': FriendlyType,
            'PacketType'  : PacketType,
            'DeviceType'  : DeviceType,
            'SourceMAC'   : source_mac,
            'SourceVendor': source_vendor,
            'DestMAC'     : dest_mac,
            'DestVendor'  : dest_vendor,
            'SSID'        : ssid,
            'Band'        : band,
            'Channel'     : channel}
        
          DBQueue.put(DBPacket)
          #insert_packet(DBPacket, db_path=PacketDB)



      #DetailsWindow.ScrollPrint(f'CaptureDate:   {timestamp}')
      #DetailsWindow.ScrollPrint(f'PacketType:    {PacketType}')
      #DetailsWindow.ScrollPrint(f'DeviceType:    {DeviceType}')
      #DetailsWindow.ScrollPrint(f'Source MAC:    {source_mac}')
      #DetailsWindow.ScrollPrint(f'Source Vendor: {source_vendor}')
      #DetailsWindow.ScrollPrint(f'Dest MAC:      {dest_mac}')
      #DetailsWindow.ScrollPrint(f'Dest Vendor:   {dest_vendor}')
      #DetailsWindow.ScrollPrint(f'SSID:          {ssid}')
      #DetailsWindow.ScrollPrint(f'Band:          {band}')
      
      #ignore routers for now
      #ignore Huawei which is my AMCREST cameras
      #if 'ROUTER' not in PacketType.upper() and 'HUAWEI' not in dest_vendor.upper() and 'HUAWEI' not in source_vendor.upper():


      '''

      #-------------------------------
      #-- Display information
      #-------------------------------
      PacketWindow.ScrollPrint(f'CaptureDate:   {timestamp}')
      if FriendlyName:
        PacketWindow.ScrollPrint(f'FriendlyName:  {FriendlyName}')    
        PacketWindow.ScrollPrint(f'FriendlyType:  {FriendlyType}')    
      PacketWindow.ScrollPrint(f'PacketType:    {PacketType}')
      PacketWindow.ScrollPrint(f'DeviceType:    {DeviceType}')
      PacketWindow.ScrollPrint(f'Source MAC:    {source_mac}')
      PacketWindow.ScrollPrint(f'Source Vendor: {source_vendor}')
      PacketWindow.ScrollPrint(f'Dest MAC:      {dest_mac}')
      PacketWindow.ScrollPrint(f'Dest Vendor:   {dest_vendor}')
      PacketWindow.ScrollPrint(f'SSID:          {ssid}')
      PacketWindow.ScrollPrint(f'Band:          {band}')
      PacketWindow.ScrollPrint(f'channel:       {channel}')
      #PacketWindow.ScrollPrint(f': {}')
      PacketWindow.ScrollPrint('---------------------------------------------------')

      '''    
    #-------------------------------
    #-- Update Header
    #-------------------------------
    packetqueue_size = PacketQueue.qsize()
    dbqueue_size     = DBQueue.qsize()
    
    HeaderLines = {
      1: f"Packets Processed:   {PacketCount}",
      2: f"Band:                {band}",
      3: f"Channel:             {str(channel).ljust(5)}",
      4: f"Packet Queue Size:   {packetqueue_size}",
      5: f"DB Queue Size:       {dbqueue_size}",
      6: f"Packets Saved to DB: {PacketsSavedToDBCount}",
      7: f"Friendly Devices:    {FriendlyDeviceCount}",
      8: f"Total Devices:       {key_count}",
    }

    HeaderWindow.set_fixed_lines(HeaderLines,Color=2)


    



    #time.sleep(0.25)







# Function to set the channel on a given Wi-Fi interface
def set_channel(interface, channel):
    global InfoWindow
    """
    Set the Wi-Fi interface to a specific channel.
    :param interface: Name of the Wi-Fi interface in monitor mode (e.g., wlan0mon)
    :param channel: Wi-Fi channel to switch to (e.g., 1-13 for 2.4 GHz or 36, 40, 44, etc. for 5 GHz)
    :return: None
    """
    try:
        result = subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'channel', str(channel)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return 0
            #InfoWindow.ScrollPrint(f"Channel: {channel}",Color=6)
        else:
            InfoWindow.ScrollPrint(f"Failed to set channel. Error: {result.stderr}",Color=6)
            return -1
    except Exception as e:
        InfoWindow.ScrollPrint(f"Error occurred while trying to set channel: {str(e)}",Color=6)

    


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
        InfoWindow.ErrorHandler(ErrorMessage,TraceMessage,'Erroor in sniff_packets function')


def format_packet(packet):
    """
    Formats a packet for output as a string.
    :param packet: Packet to format
    :return: Formatted string representation of the packet
    """
    try:
        summary = packet.summary()
        if packet.haslayer(Dot11):
            source_mac = normalize_mac(packet[Dot11].addr2)   or "Unknown"
            dest_mac   = normalize_mac(packet[Dot11].addr1)   or "Unknown"
            formatted_string = f"[Source: {source_mac:<17}] [Destination: {dest_mac:<17}] - {summary}"
        else:
            formatted_string = summary
        return formatted_string.expandtabs(4)
    except Exception as e:
        return f"Error formatting packet: {e}"




def normalize_mac(mac: str) -> str:
    return mac.upper().replace('-', ':')


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
        #InfoWindow.ScrollPrint(f"Packet Type: {packet_details['type']}")
        #for key, value in packet_details['fields'].items():
        #    InfoWindow.ScrollPrint(f"{key}: {value}")

    except Exception as e:
        InfoWindow.ScrollPrint(f"Error analyzing packet: {e}")
        traceback.print_exc()




def get_monitor_mode_interface():
    global InfoWindow
    try:
        # Run 'iw dev' to get information about wireless interfaces
        result = subprocess.run(['iw', 'dev'], stdout=subprocess.PIPE, text=True)
        output = result.stdout

        # Regex to find interface name and mode
        interfaces = re.findall(r'Interface\s+(\w+)\n.*?type\s+(\w+)', output, re.DOTALL)

        # Check which interface is in monitor mode
        for iface, mode in interfaces:
            if mode == "monitor":
                InfoWindow.ScrollPrint(f"Monitoring interface: {iface}")
                return iface

    except subprocess.CalledProcessError as e:
        print(f"Error retrieving interface information: {e}")

    return None
















def extract_oui_and_vendor_information(packet):
    """
    Extracts OUI and vendor information for all possible MAC addresses in the packet.
    
    :param packet: Scapy packet object to be analyzed.
    :return: A dictionary of MAC addresses, OUI, and corresponding vendor information.
    """
    mac_info = {}


    def get_vendor_and_oui(mac):
              
        mac_prefix = normalize_mac(mac[:8])
        if mac_prefix in vendor_cache:
          return mac_prefix, vendor_cache[mac_prefix]




        try:
          MAC = netaddr.EUI(mac)
          # Use netaddr's built-in formatting options to normalize MAC address.
          MAC.dialect = netaddr.mac_unix_expanded  # Ensures colon separator with full 6 groups
                
          vendor = MAC.oui.registration().org
        except netaddr.core.NotRegisteredError:
            vendor = 'Unknown'
            return 'Unknown','Unknown'
        except ValueError:
            return 'Unknown','Unknown'

        vendor_cache[mac_prefix] = vendor

        if mac_prefix not in oui_dict:
            oui_dict[mac_prefix] = (vendor, "No Long Description Available")

            #write to file only if we found the vendor by doing the network lookup
            if "UNKNOWN" not in vendor.upper():
              # Use a lock to prevent concurrent write access
              with write_lock:
                  with open("oui_dict.json", 'w') as json_file:
                    json.dump(oui_dict, json_file, indent=4)
                    InfoWindow.ScrollPrint("Updating OUI master file")

              InfoWindow.ScrollPrint(f"Updated OUI master file: {mac_prefix} - {vendor}", Color=5)

        return mac_prefix, vendor



    # Extract MAC addresses from various layers and retrieve their OUI and vendor info

    # Ethernet Layer
    if packet.haslayer(Ether):
        src_mac = normalize_mac(packet[Ether].src)
        dst_mac = normalize_mac(packet[Ether].dst)
        if src_mac:
            src_oui, src_vendor = get_vendor_and_oui(src_mac)
            mac_info['Ethernet Source MAC'] = {'MAC': src_mac, 'OUI': src_oui, 'Vendor': src_vendor}
        if dst_mac:
            dst_oui, dst_vendor = get_vendor_and_oui(dst_mac)
            mac_info['Ethernet Destination MAC'] = {'MAC': dst_mac, 'OUI': dst_oui, 'Vendor': dst_vendor}

    # ARP Layer
    if packet.haslayer(ARP):
        src_mac = normalize_mac(packet[ARP].hwsrc)
        dst_mac = normalize_mac(packet[ARP].hwdst)
        if src_mac:
            src_oui, src_vendor = get_vendor_and_oui(src_mac)
            mac_info['ARP Source MAC'] = {'MAC': src_mac, 'OUI': src_oui, 'Vendor': src_vendor}
        if dst_mac:
            dst_oui, dst_vendor = get_vendor_and_oui(dst_mac)
            mac_info['ARP Destination MAC'] = {'MAC': dst_mac, 'OUI': dst_oui, 'Vendor': dst_vendor}

    # 802.11 Wireless Layer
    if packet.haslayer(Dot11):
        # Destination MAC
        if hasattr(packet, 'addr1') and packet.addr1:
            dst_mac = normalize_mac(packet.addr1)
            dst_oui, dst_vendor = get_vendor_and_oui(dst_mac)
            mac_info['WIFI Destination MAC'] = {'MAC': dst_mac, 'OUI': dst_oui, 'Vendor': dst_vendor}

        # Source MAC
        if hasattr(packet, 'addr2') and packet.addr2:
            src_mac = normalize_mac(packet.addr2)
            src_oui, src_vendor = get_vendor_and_oui(src_mac)
            mac_info['WIFI Source MAC'] = {'MAC': src_mac, 'OUI': src_oui, 'Vendor': src_vendor}

        # BSSID
        if hasattr(packet, 'addr3') and packet.addr3:
            bssid_mac = normalize_mac(packet.addr3)
            bssid_oui, bssid_vendor = get_vendor_and_oui(bssid_mac)
            mac_info['WIFI BSSID'] = {'MAC': bssid_mac, 'OUI': bssid_oui, 'Vendor': bssid_vendor}

        # Additional MAC Address (usually used in WDS frames)
        if hasattr(packet, 'addr4') and packet.addr4:
            additional_mac = normalize_mac(packet.addr4)
            additional_oui, additional_vendor = get_vendor_and_oui(additional_mac)
            mac_info['WIFI Additional MAC'] = {'MAC': additional_mac, 'OUI': additional_oui, 'Vendor': additional_vendor}

    # VLAN Tagged Frame Layer
    if packet.haslayer(Dot1Q):
        src_mac = normalize_mac(packet[Dot1Q].src)
        if src_mac:
            src_oui, src_vendor = get_vendor_and_oui(src_mac)
            mac_info['VLAN Tagged MAC'] = {'MAC': src_mac, 'OUI': src_oui, 'Vendor': src_vendor}

    # 802.3 Layer (for LLC Ethernet packets)
    if packet.haslayer(Dot3):
        src_mac = normalize_mac(packet[Dot3].src)
        if src_mac:
            src_oui, src_vendor = get_vendor_and_oui(src_mac)
            mac_info['802.3 Source MAC'] = {'MAC': src_mac, 'OUI': src_oui, 'Vendor': src_vendor}

    return mac_info


def identify_packet_layers(packet):
    """
    Identifies all the layers present in the packet and returns a list of protocol names.

    :param packet: Scapy packet object to be analyzed.
    :return: A list of strings representing the identified layers.
    """
    layers = []

    # Use a while loop to iterate through all layers
    current_layer = packet
    while current_layer:
        # Append the name of the current layer's class to the list
        layers.append(current_layer.__class__.__name__)
        # Move to the next layer (payload) in the packet
        current_layer = current_layer.payload

    # If no known layers found, append "Unknown Layer"
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







# Function to print statistics about the OUI dictionary
def print_oui_stats(oui_dict,InfoWindow):


    InfoWindow.ScrollPrint("=== OUI Dictionary Statistics ===")
    
    # Total number of entries
    total_entries = len(oui_dict)
    InfoWindow.ScrollPrint(f"Total Number of OUI Entries: {total_entries}")

    # Count occurrences of vendors in the OUI dictionary
    vendor_counter = Counter()
    for oui, (short_desc, long_desc) in oui_dict.items():
        vendor_counter[short_desc] += 1

    # Number of unique vendors
    total_unique_vendors = len(vendor_counter)
    InfoWindow.ScrollPrint(f"Total Number of Unique Vendors: {total_unique_vendors}")

    # Vendors with multiple OUIs
    vendors_with_multiple_ouis = {vendor: count for vendor, count in vendor_counter.items() if count > 1}
    InfoWindow.ScrollPrint(f"Vendors with Multiple OUIs: {len(vendors_with_multiple_ouis)}")

    # Print top vendors with the most OUI entries
    InfoWindow.ScrollPrint("Top 25 Vendors with the Most OUI Entries:")
    for vendor, count in vendor_counter.most_common(25):
        InfoWindow.ScrollPrint(f"{vendor}: {count} entries")







###########################################################
#  MAIN PROCESSING                                        #
###########################################################

def channel_hopper(interface, hop_interval):
    global current_channel_info

    channel_result = 0

    # Define available channels for 2.4 GHz and 5 GHz
    channels_24ghz = list(range(1, 14))  # Channels 1 to 13 for 2.4 GHz
    
    #channels_5ghz = [36, 40, 44, 48, 149, 153, 157, 161, 165]  # Common 5 GHz channels
    
    #Master list 5GHz channels
    channels_5ghz = [
      36, 38, 40, 42, 44, 46, 48, 
      52, 54, 56, 58, 60, 62, 64, 
      100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 
      132, 134, 136, 138, 140, 142, 144,
      149, 151, 153, 155, 157, 159, 161, 163, 165, 167, 169, 171, 173]


    # Combine all channels into one list
    all_channels = channels_24ghz + channels_5ghz
    channel_index = 0

    try:
        while True:
            # Set the interface to the current channel
            current_channel = all_channels[channel_index]
            
            #keep setting channel until we find one that is not disabled
            while channel_result != 0:
              InfoWindow.ScrollPrint("Channel Skipped",Color=3)
              channel_result = set_channel(interface, current_channel)



            # Update the global channel information
            if current_channel in channels_24ghz:
                current_channel_info = {
                    "channel": current_channel,
                    "band": "2.4 GHz",
                    "frequency": 2407 + current_channel * 5
                }
            elif current_channel in channels_5ghz:
                current_channel_info = {
                    "channel": current_channel,
                    "band": "5 GHz",
                    "frequency": 5000 + (current_channel * 5)
                }

            #InfoWindow.ScrollPrint(f"{current_channel_info['band']} band - Channel {current_channel} - Freq. {current_channel_info['frequency']} MHz",Color=5)


            # Move to the next channel (wrap around if at the end)
            channel_index = (channel_index + 1) % len(all_channels)

            # Wait for the specified hop interval before switching channels again
            time.sleep(hop_interval)

    except KeyboardInterrupt:
        print("Channel hopping stopped by user.")




# Integrate channel hopping in the main function
def main(stdscr):
    global HeaderWindow
    global PacketWindow
    global InfoWindow
    global DetailsWindow
    global oui_dict
    global friendly_devices_dict
    global hop_interval
    global PacketDB
    global DBConnection
    

    looping = True
    

    # Call the helper function to initialize curses
    textwindows.initialize_curses(stdscr)

    ScreenHeight, ScreenWidth = textwindows.get_screen_dimensions(stdscr)

    # Calculate window sizes for display
    max_y, max_x = stdscr.getmaxyx()
    window_width = max_x // HorizontalWindowCount
    

    # Create display windows
    fixed_lines = [
        (0, ""),
        (1, ""),
        (2, ""),
        (3, ""),
        (4, ""),
        (5, ""),
        (6, ""),
        (7, ""),
        (8, ""),
        (9, ""),
    ]
   
    HeaderWindow  = textwindows.HeaderWindow(name='HeaderWindow', title='Header',    rows= HeaderHeight, columns=window_width, y1=0, x1=0,                                     ShowBorder='Y', BorderColor=2, TitleColor=3,fixed_lines=fixed_lines)
    PacketWindow  = textwindows.TextWindow  (name='PacketWindow', title='Packets',   rows=max_y - 1,     columns=window_width, y1=(HeaderHeight + 1), x1=0,                    ShowBorder='Y', BorderColor=2, TitleColor=2)
    DetailsWindow = textwindows.TextWindow  (name='DetailsWindow',title='Details',   rows=max_y - 1,     columns=window_width, y1=(HeaderHeight + 1), x1=window_width + 1,     ShowBorder='Y', BorderColor=2, TitleColor=2)
    InfoWindow    = textwindows.TextWindow  (name='InfoWindow',   title='Extra Info',rows=max_y - 1,     columns=window_width, y1=(HeaderHeight + 1), x1=window_width * 2 + 1, ShowBorder='Y', BorderColor=2, TitleColor=2)



    # Refresh windows for initial setup
    HeaderWindow.DisplayTitle('Sentinel 1.0')
    HeaderWindow.refresh()

    PacketWindow.DisplayTitle('Packet Info')
    PacketWindow.refresh()
    
    InfoWindow.DisplayTitle('Information')
    InfoWindow.refresh()
    
    DetailsWindow.DisplayTitle('Details')
    DetailsWindow.refresh()

    
    InfoWindow.ScrollPrint(f"Height x Width {ScreenHeight}x{ScreenWidth}")    

    # Load the OUI dictionary
    oui_dict = load_oui_dict_from_json("oui_dict.json")
    print_oui_stats(oui_dict, InfoWindow)


    # Load the friendly devices dictionary
    friendly_devices_dict = load_friendly_devices_dict("FriendlyDevices.json")
    

    # Get the Wi-Fi interface in monitor mode
    interface = get_monitor_mode_interface()
    if interface is None:
        InfoWindow.ScrollPrint("ERROR: No interface found in monitor mode. Exiting...")
        return


    


    # Create and start the packet processing thread
    packet_processing_thread = threading.Thread(target=process_PacketQueue, name="PacketProcessingThread")
    packet_processing_thread.daemon = True  # Set as daemon so it exits with the main program
    packet_processing_thread.start()

    # Create and start the DB processing thread
    DB_processing_thread = threading.Thread(target=process_DBQueue, name="DBProcessingThread")
    DB_processing_thread.daemon = True  # Set as daemon so it exits with the main program
    DB_processing_thread.start()

    # Start the channel hopper thread
    hopper_thread = threading.Thread(target=channel_hopper, args=(interface, hop_interval), name="ChannelHopperThread")
    hopper_thread.daemon = True
    hopper_thread.start()

    # Start packet sniffing thread
    sniff_thread = threading.Thread(target=sniff_packets, args=(interface,), name="SniffingThread")
    sniff_thread.daemon = True  # Allows the program to exit even if the thread is running
    sniff_thread.start()

    try:
        # Keep the curses interface running
        while True:
            time.sleep(1)
            # Update the curses windows if needed
            #PacketWindow.window.touchwin()
            #PacketWindow.refresh()
            #InfoWindow.window.touchwin()
            #InfoWindow.refresh()
            #DetailsWindow.window.touchwin()
            #DetailsWindow.refresh()

    except KeyboardInterrupt:
        InfoWindow.ScrollPrint("Stopping...")

# Call main
curses.wrapper(main)




