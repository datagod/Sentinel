'''
Notes: 
 - Do not write to the windows from multiple threads as this will lead to strange artifacts
 - look into generating maps with Folium and serving them up via webserver
 - modify scrollprint to add a string to a window_queue (windowname, string)
 - a separate thread will read the window_queue and write the string to the correct window
 - store raw packets for further processing by A.I. to fingerprint devices that have modified their MAC repeatedly
 - find out if friendly cache is working
 - look into seeing what we can pull out of RadioTap packet layers

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
from collections import Counter, defaultdict
import gps
import inspect
from functools import wraps
from cachetools import TTLCache
import termios, tty, sys

import netaddr
import threading
import argparse
from colorama import Fore, Back, Style, init
import pyfiglet
import shutil
import pprint
from typing import List, Tuple


from scapy.all import *
from scapy.layers.l2 import Dot3, Dot1Q, Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dhcp import DHCP
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp

# Import the device type dictionary from the other file
from device_type_dict import device_type_dict


#Global Variables
oui_dict       = None
vendor_cache   = {}
write_lock     = threading.Lock()
gps_lock       = threading.Lock()  # New lock for GPS synchronization
gps_stop_event = threading.Event()
profile_lock   = threading.Lock()
profiling_data = {}                # Dictionary to store function run times

#Parameters
curses_enabled          = True
show_friendly           = True

#Packet Stuff
current_channel_info    = {"channel": None, "band": None, "frequency": None}
displayed_packets_cache = TTLCache(maxsize=10000, ttl=900)   #entry expires after 15 minutes
friendly_device_cache   = TTLCache(maxsize=10000, ttl=3600)  #entry expires after 1 hour
key_count               = 0
friendly_devices_dict   = None
PacketCount             = 0
friendly_key_count      = 0
PacketQueue             = queue.Queue()
DBQueue                 = queue.Queue()
PacketDB                = "packet.db"
DBConnection            = None
DBReports               = None
PacketsSavedToDBCount   = 0
latitude                = None
longitude               = None
current_latitude        = None
current_longitude       = None
ProcessedPacket         = None
MobileCount             = 0
RouterCount             = 0
OtherCount              = 0
DeviceTypeDict          = defaultdict(set)

#Timers
hop_interval      = 1    #Interval in seconds between channel hops
hop_modifier      = 5    #divides modifies the hop interval so we don't wait as long on 5Ghz channels 
main_interval     = 1    #Interval in seconds for the main loop
gps_interval      = 2    #Interval in seconds for the GPS check
HeaderUpdateSpeed = 5
last_time         = time.time()  #time in seconds since the epoch
keyboard_interval = 1    #Interval in seconds to check for keypress


#Windows variables
HeaderWindow  = None
InfoWindow    = None
PacketWindow  = None
DetailsWindow = None
RawWindow     = None
HorizontalWidthUnits = 5
HeaderHeight  = 15
HeaderWidth   = 80
ScreenWidthOverride = 240

#Console variables
console_width            = shutil.get_terminal_size().columns
console_height           = shutil.get_terminal_size().lines
console_region           = None
console_start_row        = 16
console_stop_row         = console_height
console_header_start_row = 4
console_region_title = "Time     Friendly         PacketType     DeviceType      SourceMac         SourceVendor         SSID            BandSignal"



      


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



#------------------------------------------------------------------------------
# ASCII Functions                                                            --
#------------------------------------------------------------------------------

def clear_screen_ASCII():
    print("\033[2J\033[H", end="", flush=True)  # Clear screen with ANSI escape code



#------------------------------------------------------------------------------
# Keyboard Functions                                                         --
#------------------------------------------------------------------------------


def ProcessKeypress(Key):
  global show_friendly
  global show_routers
  global console_region
  
  # q = quit
  # t = restart in textwindow mode
  # r = restart in raw mode
    
  if (Key == "p" or Key == " "):
    time.sleep(5)


  #elif (Key == '1'):
  #      print(Fore.RED,end="", flush=True)
  #elif (Key == '2'):
  #      print(Fore.GREEN,end="", flush=True)
  #elif (Key == '3'):
  #      print(Fore.BLUE,end="", flush=True)
  elif (Key == '4'):
        print(Fore.YELLOW,end="", flush=True)
  elif (Key == '5'):
        print(Fore.MAGENTA,end="", flush=True)
  elif (Key == '6'):
        print(Fore.CYAN,end="", flush=True)
  elif (Key == '7'):
        print(Fore.WHITE,end="", flush=True)



  elif (Key == "q"):
    print(f"\033[11;1H",flush=True)
    print(Fore.RED,end="", flush=True)
    print(pyfiglet.figlet_format("            QUIT            ", font='pagga',width=console_width))
    print('                                                  ')
    print('                                                  ')
    print('                                                  ')
    print('                                                  ')
    print('                                                  ')
    exit()

  #----------------------------
  #-- Toggle Friendly
  #----------------------------
  elif (Key == "f"):
    if show_friendly == False:
      if curses_enabled:
        log_message("SHOW FRIENDLY ON")
      else:
        print(f"\033[{console_start_row};1H",flush=True)
        print(pyfiglet.figlet_format("      SHOW FRIENDLY          ", font='pagga',width=console_width))
    else:
      if curses_enabled:
        log_message("SHOW FRIENDLY OFF")
      else:
        print(f"\033[{console_start_row};1H")
        print(pyfiglet.figlet_format("      HIDE FRIENDLY          ", font='pagga',width=console_width))

    show_friendly = not(show_friendly)
    DisplayHeader()


  #----------------------------
  #-- Toggle Routers
  #----------------------------
  elif (Key == "r"):
    if show_routers == False:
      if curses_enabled:
        log_message("SHOW ROUTERS ON")
      else:
        print(f"\033[{console_start_row};1H")
        print(pyfiglet.figlet_format("      SHOW ROUTERS          ", font='pagga',width=console_width))
    else:
      if curses_enabled:
        log_message("SHOW ROUTERS OFF")
      else:
        print(f"\033[{console_start_row};1H")
        print(pyfiglet.figlet_format("      HIDE ROUTERS          ", font='pagga',width=console_width))

    show_routers = not(show_routers)
    DisplayHeader()


  #----------------------------
  #-- Restart
  #----------------------------
  elif (Key == "R"):
    os.system("stty sane")
    print(f"\033[{console_start_row};1H",flush=True)
    print(Fore.RED,end='',flush=True)
    print(pyfiglet.figlet_format("         RESTART        ", font='pagga',width=console_width))
    print('')
    print('')
    os.execl(sys.executable, sys.executable, *sys.argv)


  #-----------------------------------
  #-- Toggle TextWindows / Raw modes
  #-----------------------------------
  #Switch from Windows to Raw or Raw to Windows and restart
  elif (Key == "t"):
    #clear the screen
    #os.system('cls' if os.name == 'nt' else 'clear')    
    clear_screen_ASCII()
    os.system("stty sane")

    print(f"\033[{console_start_row};1H",flush=True)
    print(Fore.RED,end='')
    print(pyfiglet.figlet_format("     TOGGLE WINDOWS/RAW        ", font='pagga',width=console_width))
    
    if curses_enabled == False:
      custom_params = ["--Raw","N"]
    else:
      custom_params = ["--Raw","Y"]

    #change the start parameters
    new_argv = [sys.argv[0]] + custom_params

    #Restart python program
    os.execl(sys.executable, sys.executable, *new_argv)

  
  #----------------------------
  #-- Report 1
  #----------------------------
  
  elif Key == '1':  
      ProduceReport_TopDevices(TheCount=25)

  #----------------------------
  #-- Report 2
  #----------------------------
  
  elif Key == '2':  
      ProduceReport_TopMobile(TheCount=30)

  #----------------------------
  #-- Report 3
  #----------------------------
  
  elif Key == '3':  
      ProduceReport_RecentIntruders(TheCount=30)



  #-----------------------------------
  #-- Clear the console
  #-----------------------------------
  elif (Key == 'c'):
    os.system("stty sane")
    print(f"\033[1;1H", end="",flush=True)
    print("\033[0J", end="")
    print(f"\033[0;0H", end="", flush=True)  # Explicitly set cursor to row 0, column 0

    if not curses_enabled:
        print(Fore.RED,end="", flush=True)
        print(pyfiglet.figlet_format("    SENTINEL PASSIVE SURVEILLANCE   ",font='pagga',justify='left',width=console_width))
        print(Fore.GREEN,end="", flush=True)
        console_region.current_row = console_region.start_row +1
        console_region.print_line(text=console_region_title,line=console_region.title_row)        

    DisplayHeader()

  


def get_keypress():
    """Read a single keypress without clearing the screen."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        key = sys.stdin.read(1)

        if key == '\x1b':  # Escape character
            key += sys.stdin.read(2)  # Read additional characters

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return key





def DisplayHeader():
    global HeaderWindow
    global PacketWindow
    global InfoWindow
    global DetailsWindow
    global RawWindow
    global oui_dict
    global friendly_devices_dict
    global current_channel_info
    global displayed_packets_cache
    global friendly_device_cache
    global key_count
    global PacketCount
    global friendly_key_count
    global DBQueue
    global PacketsSavedToDBCount
    global gps_lock
    global console_region
    global show_friendly
    global ProcessedPacket


    try:


        #-------------------------------
        #-- Update Header
        #-------------------------------
    
    
        band     = str(current_channel_info.get('band','0')  if current_channel_info else '0')
        channel  = str(current_channel_info.get('channel','0') if current_channel_info else '0')
            
        packetqueue_size = PacketQueue.qsize()
        dbqueue_size     = DBQueue.qsize()
    
        # Pre-process values for formatting
        packet_count = str(PacketCount)[:8]
        friendly     = 'Yes' if show_friendly else 'No'
        routers      = 'Yes' if show_routers else 'No'
        time_display = datetime.now().replace(microsecond=0)
        latitude     = str(current_latitude or "N/A"[:10])
        longitude    = str(current_longitude or "N/A"[:10])
        filler       = "            "
        

        # Define the HeaderLines dictionary with clean formatting
        HeaderLines = {
                1: f"Packets Processed:   {packet_count:<12}"           + filler + f"ShowFriendly: {friendly:<5}",
                2: f"Band:                {band:<12}"                   + filler + f"ShowRouters:  {routers:<5}",
                3: f"Channel:             {channel:<12}"                + filler,
                4: f"Packet Queue Size:   {packetqueue_size:<12}"       + filler,
                5: f"DB Queue Size:       {dbqueue_size:<12}"           + filler,
                6: f"Packets Saved to DB: {PacketsSavedToDBCount:<12}"  + filler,
                7: f"Friendly Devices:    {friendly_key_count:<12}"     + filler,
                8: f"Total Devices:       {key_count:<12}"              + filler,
                9: f"Time:                {time_display}"               + filler,
               10: f"Longitude:           {longitude}"                  + filler,
               11: f"Latitude:            {latitude}"                   + filler

        }

        if curses_enabled:
            HeaderWindow.set_fixed_lines(HeaderLines,Color=2)
        else:
            if (show_friendly == True)  or (ProcessedPacket.FriendlyDevice == False ):
                PrintConsoleHeader(HeaderLines,console_header_start_row)

    except Exception as e:
        TraceMessage = traceback.format_exc()
        if curses_enabled:
          InfoWindow.ErrorHandler(str(e), TraceMessage, "**Display Header Error**")
        else:
          ErrorHandler(TraceMessage)
        






def ProcessPacketInfo():
    global HeaderWindow
    global PacketWindow
    global InfoWindow
    global DetailsWindow
    global RawWindow
    global oui_dict
    global friendly_devices_dict
    global current_channel_info
    global displayed_packets_cache
    global friendly_device_cache
    global key_count
    global PacketCount
    global friendly_key_count
    global DBQueue
    global PacketsSavedToDBCount
    global gps_lock
    global console_region
    global show_friendly
    global ProcessedPacket
    global DeviceTypeDict
    global RouterCount
    global MobileCount
    global OtherCount

    channel         = 0
    band            = 0
    timestamp       = datetime.now()
    regular_color   = Fore.GREEN

    if not ProcessedPacket:
        log_message("ProcessPacketInfo: There was no packet to process!")
        return

    # Create a unique key for the packet based on important fields
    ProcessedPacket.source_mac, ProcessedPacket.ssid, ProcessedPacket.source_vendor, ProcessedPacket.DeviceType = replace_none_with_unknown(ProcessedPacket.source_mac, ProcessedPacket.ssid, ProcessedPacket.source_vendor, ProcessedPacket.DeviceType)
    packet_key = (ProcessedPacket.source_mac, ProcessedPacket.ssid, ProcessedPacket.source_vendor, ProcessedPacket.DeviceType)



    #Count number of different devices trackes during this session
    RouterCount = 0
    MobileCount = 0
    OtherCount  = 0
    if PacketCount % HeaderUpdateSpeed == 0:
    # Iterate through DeviceTypeDict once
        for DeviceType, macs in DeviceTypeDict.items():
            mac_count = len(macs)
            if "ROUTER" in DeviceType.upper():
                RouterCount += len(macs)
            elif "MOBILE" in DeviceType.upper():
                MobileCount += len(macs)
            else:
                OtherCount += len(macs)
        #RouterCount = sum(len(macs) for DeviceType, macs in DeviceTypeDict.items() if 'ROUTER' in DeviceType.upper())
        #MobileCount = sum(len(macs) for DeviceType, macs in DeviceTypeDict.items() if 'MOBILE' in DeviceType.upper())
        #OtherCount  = sum(len(macs) for DeviceType, macs in DeviceTypeDict.items()) - RouterCount - MobileCount

        max_length = max(len(str(count)) for count in [RouterCount, MobileCount, OtherCount])
        if(not curses_enabled):
          console_region.print_large(f"Routers: {RouterCount:>{max_length}}", font="pagga", color=Fore.YELLOW, start_row=5,  start_col=70)
          console_region.print_large(f"Mobile:  {MobileCount:>{max_length}}", font="pagga", color=Fore.YELLOW, start_row=8,  start_col=70)
          console_region.print_large(f"Other:    {OtherCount:>{max_length}}",  font="pagga", color=Fore.YELLOW, start_row=11, start_col=70)



    #Check for friendly device
    result = search_friendly_devices(ProcessedPacket.source_mac,friendly_devices_dict)
    if result:
        ProcessedPacket.FriendlyDevice = True
        ProcessedPacket.FriendlyName   = result.get('FriendlyName', '') or ''
        ProcessedPacket.FriendlyType   = result.get('Type','')          or '' 
        ProcessedPacket.FriendlyBrand  = result.get('Brand','')         or ''

        # Create a unique key for the friendly packet based on important fields
        friendly_device_key = (ProcessedPacket.FriendlyName, ProcessedPacket.FriendlyType)
        #add to cache
        friendly_device_cache[friendly_device_key] = True
        friendly_key_count = len(friendly_device_cache)

      



    # To declutter the screen we don't display items that are in the cache
    # the cache expires after X minutes
    if packet_key not in displayed_packets_cache:
      #add to cache
      displayed_packets_cache[packet_key] = True
      key_count = len(displayed_packets_cache)
  
      #DetailsWindow.QueuePrint(f"{key_count} - {FriendlyName} - {FriendlyType} - {FriendlyBrand} - {ssid}")
      if curses_enabled: 
  
    
          if show_friendly and ProcessedPacket.FriendlyDevice == True:
            NameString = f"{str(ProcessedPacket.FriendlyName)} - {str(ProcessedPacket.FriendlyType)}"
            
            FormattedString = format_into_columns(DetailsWindow.columns, 
                f"{NameString[:30]:<30}",   
                ProcessedPacket.source_mac,
                ProcessedPacket.FriendlyBrand,   
                ProcessedPacket.ssid, 
                (f"{ProcessedPacket.band} {ProcessedPacket.channel} {ProcessedPacket.signal}dB"))
            DetailsWindow.QueuePrint(FormattedString)



          else:
            
            NameString = f"{str(ProcessedPacket.FriendlyName)} - {str(ProcessedPacket.FriendlyType)}"

            #Format a string for the Detail Window display
            FormattedString = format_into_columns(
                DetailsWindow.columns, 
                f"{NameString[:30]:<30}",   
                (ProcessedPacket.source_mac if (ProcessedPacket.source_mac != 'UNKNOWN' and ProcessedPacket.source_mac is not None) else ProcessedPacket.source_oui) , 
                f"{ProcessedPacket.source_vendor} {ProcessedPacket.source_oui}",
                ProcessedPacket.ssid, 
                (f"{ProcessedPacket.band} {ProcessedPacket.channel} {ProcessedPacket.signal}dB")
                )
            DetailsWindow.QueuePrint(FormattedString,Color=3)

            #Show details in the Info window
            InfoWindow.QueuePrint('INTRUDER DETAILS',Color=1)
            InfoWindow.QueuePrint(f'CaptureDate:   {timestamp}')
            InfoWindow.QueuePrint(f'FriendlyName:  {ProcessedPacket.FriendlyName}')    
            InfoWindow.QueuePrint(f'FriendlyType:  {ProcessedPacket.FriendlyType}')    
            InfoWindow.QueuePrint(f'PacketType:    {ProcessedPacket.PacketType}')
            InfoWindow.QueuePrint(f'DeviceType:    {ProcessedPacket.DeviceType}')
            InfoWindow.QueuePrint(f'Source MAC:    {ProcessedPacket.source_mac}')
            InfoWindow.QueuePrint(f'Source Vendor: {ProcessedPacket.source_vendor}')
            InfoWindow.QueuePrint(f'Dest MAC:      {ProcessedPacket.dest_mac}')
            InfoWindow.QueuePrint(f'Dest Vendor:   {ProcessedPacket.dest_vendor}')
            InfoWindow.QueuePrint(f'SSID:          {ProcessedPacket.ssid}')
            InfoWindow.QueuePrint(f'Band:          {ProcessedPacket.band}')
            InfoWindow.QueuePrint(f'channel:       {ProcessedPacket.channel}')
            InfoWindow.QueuePrint(f'signal:        {ProcessedPacket.signal} dB')
            InfoWindow.QueuePrint('---------------------------------------------------')
      


    
      #--------------------------------------
      #-- Save processed packet to DB Queue
      #--------------------------------------
      # For now we save Intruder details to the database
      DBPacket = {
        'CaptureDate' : ProcessedPacket.timestamp,
        'FriendlyName': ProcessedPacket.FriendlyName,
        'FriendlyType': ProcessedPacket.FriendlyType,
        'PacketType'  : ProcessedPacket.PacketType,
        'DeviceType'  : ProcessedPacket.DeviceType,
        'SourceMAC'   : ProcessedPacket.source_mac,
        'SourceVendor': ProcessedPacket.source_vendor,
        'DestMAC'     : ProcessedPacket.dest_mac,
        'DestVendor'  : ProcessedPacket.dest_vendor,
        'SSID'        : ProcessedPacket.ssid,
        'Band'        : ProcessedPacket.band,
        'Channel'     : ProcessedPacket.channel,
        'Latitude'    : current_latitude,
        'Longitude'   : current_longitude,
        'Signal'      : ProcessedPacket.signal
        }
    
      DBQueue.put(DBPacket)
      #insert_packet(DBPacket, db_path=PacketDB)




      #print a row of activity to the console print region
      color = Fore.GREEN
      if (curses_enabled == False) and (show_friendly == True or (show_friendly == False and ProcessedPacket.FriendlyName == None)):
          # Create a dense single-line string for console output
          if ProcessedPacket.FriendlyName == None:
              ProcessedPacket.FriendlyName = '??'
              regular_color = Fore.LIGHTRED_EX
          if band == None:
              band = '??'
            
          BandSignal = f"{ProcessedPacket.band} {ProcessedPacket.channel} {ProcessedPacket.signal}dB | "

          ProcessedPacket.PacketType = ProcessedPacket.PacketType.replace("802.11","")
            
          console_output = (
            
                #f"{str(PacketCount)[:8]:<8}  "
                f"{str(timestamp)[11:19]:<8} "
                f"{ProcessedPacket.FriendlyName[:15]:<15} "
                f"{ProcessedPacket.PacketType[:15]:<15} "
                f"{ProcessedPacket.DeviceType[:15]:<15} "
                f"{ProcessedPacket.source_mac[:17]:<17} "
                f"{ProcessedPacket.source_vendor[:20]:<20} "
                f"{ProcessedPacket.ssid or 'N/A'[:15]:<15} "
                f"{BandSignal[:15]:<15} "
                #f"{current_latitude or 'N/A'[:10]:<10} | "
                #f"{current_longitude or 'N/A'[:10]:<10}"
            )
            
            
            # We will ignore RadioTap packets for now
            #if (packet.haslayer(RadioTap)):
            #    radiotap_header = packet[RadioTap]
            #    #Print the Radiotap header details
            #    print(radiotap_header.show())
            #    # Access the presence mask
            #    presence_mask = radiotap_header.present
            #    print(f"Presence Mask: {presence_mask}")
            #    return
            
          #if ('UNKNOWN' not in ProcessedPacket.source_mac):
          console_region.region_print_line(console_output,highlight_color=Fore.WHITE, regular_color=regular_color)













def get_curses_color_pair(fore_color):
    color_map = {
        Fore.RED: 1,      # Maps to curses color pair 1 (COLOR_RED on COLOR_BLACK)
        Fore.GREEN: 2,    # Maps to curses color pair 2 (COLOR_GREEN on COLOR_BLACK)
        Fore.YELLOW: 3,   # Maps to curses color pair 3 (COLOR_YELLOW on COLOR_BLACK)
        Fore.BLUE: 4,     # Maps to curses color pair 4 (COLOR_BLUE on COLOR_BLACK)
        Fore.MAGENTA: 5,  # Maps to curses color pair 5 (COLOR_MAGENTA on COLOR_BLACK)
        Fore.CYAN: 6,     # Maps to curses color pair 6 (COLOR_CYAN on COLOR_BLACK)
        Fore.WHITE: 7,    # Maps to curses color pair 7 (COLOR_WHITE on COLOR_BLACK)
        Fore.RESET: 0     # Default/reset color (no color pair applied)
    }
    # Return the corresponding color pair or default to 0 if not found
    return color_map.get(fore_color, 2)


def log_message(message, window=None,color=2,ShowTime=None):
    """Logs a message using curses or standard print."""

    if isinstance(color, str):
      color = get_curses_color_pair(color)

    if ShowTime:
       message = f"{str(datetime.now())[11:19]:<8} - {message}"
       

    try:
        if curses_enabled:
            if window:
              window.QueuePrint(message,Color=color)
            else:        
              InfoWindow.QueuePrint(message,Color=color)
        else:
            console_region.region_print_line(message)
    except Exception as e:
        # Fallback to standard print if all else fails
        print(f"Error logging message: {e}")
        print(message)




class PacketInformation():
    def __init__(self):
        self.source_mac     = 'UNKNOWN'
        self.dest_mac       = 'UNKNOWN'
        self.source_vendor  = ''
        self.dest_vendor    = ''
        self.source_oui     = ''
        self.ssid           = ''
        self.DeviceType     = ''
        self.PacketType     = ''
        self.signal         = None
        self.channel        = 0
        self.band           = 0
        self.timestamp      = datetime.now()
        self.FriendlyDevice = False
        self.FriendlyName   = None
        self.FriendlyType   = None
        self.FriendlyBrand  = None
        self.latitude       = None
        self.longitude      = None
        self.packet_layers  = None
        self.packet_info    = None
        self.packet_details = None
        self.mac_details    = None
        self.Packet         = None
        self.PacketType     = None
        
     


  

def initialize_console_region(start_row, stop_row):
    """
    Initialize the global console region with specified start and end rows.
    
    Parameters:
    start_row (int): The starting row of the region.
    stop_row (int): The ending row of the region.
    """
    print("Setting up the console region")
    global console_region
    console_region = ConsoleRegion(start_row, stop_row)





class ConsoleRegion:
    def __init__(self, start_row, stop_row, default_color=Fore.GREEN):
        """
        Initialize a console region for printing.
        
        Parameters:
        start_row (int): The starting row of the region.
        stop_row (int): The ending row of the region.
        default_color (str): The default color for printing text.
        """
        self.title_row = start_row
        self.start_row = start_row + 1
        self.stop_row = stop_row
        self.current_row    = self.start_row
        self.previous_row   = start_row + 1
        self.previous_text  = ''
        self.previous_color = default_color 
        self.current_color  = default_color  # Store the current color

    def region_print_line(self, text, align="left", highlight_color=Fore.WHITE,regular_color=Fore.GREEN):
        """
        Print a string to the next line in the region, resetting the previous line.
        
        Parameters:
        text (str): The text to print.
        align (str): Text alignment ('left', 'center', 'right').
        color (str): The color to use for this print. Defaults to the last used color.
        """
        global console_width  # Assuming console_width is defined globally
        color = highlight_color or regular_color  # Use provided color or fallback to remembered color
        self.current_color = color  # Remember this color for subsequent prints

        # Adjust text alignment
        if align == "center":
            text = text.center(console_width)
        elif align == "right":
            text = text.rjust(console_width)
        else:
            text = text.ljust(console_width)

        # Truncate text if it exceeds console width
        text = text[:console_width]

        # Reset the previous line if it's within bounds
        if hasattr(self, "previous_row") and self.previous_row:
            print(self.previous_color, end="", flush=True)
            print(f"\033[{self.previous_row};1H{self.previous_text}", end="")
            print("\033[K", end="")  # Clear the rest of the line

        #Print the current line
        #Current line is highlighted, then goes back to the regular color during the next print
        print(highlight_color, end="", flush=True)
        print(f"\033[{self.current_row};1H{text}", end="")
        print("\033[K", end="")  # Clear any leftover content on the line
        print(Style.RESET_ALL, end="", flush=True)  # Reset to default style

        # Store the current line's information for resetting next time
        self.previous_row   = self.current_row
        self.previous_text  = text
        self.previous_color = regular_color

        # Increment the current row and wrap around if it exceeds the stop row
        self.current_row += 1
        if self.current_row > self.stop_row:
            self.current_row = self.start_row

    def print_line(self, text, align="left", line=0, color=None):
        """
        Print a string to the specified line in the region.
        
        Parameters:
        text (str): The text to print.
        align (str): Text alignment ('left', 'center', 'right').
        line (int): The line to print to (absolute row number).
        color (str): The color to use for this print. Defaults to the last used color.
        """
        global console_width  # Assuming console_width is defined globally
        color = color or self.current_color  # Use provided color or fallback to remembered color
        self.current_color = color  # Remember this color for subsequent prints

        # Adjust text alignment
        if align == "center":
            text = text.center(console_width)
        elif align == "right":
            text = text.rjust(console_width)
        else:
            text = text.ljust(console_width)

        # Truncate text if it exceeds console width
        text = text[:console_width]

        # Print the specified line
        print(color, end="", flush=True)
        print(f"\033[{line};1H{text}", end="")
        print("\033[K", end="")  # Clear any leftover content on the line
        print(Style.RESET_ALL, end="", flush=True)  # Reset to default style



    def print_large(self, number, font="pagga", color=None, start_row=None, start_col=1):
        """
        Print a large-format number in the specified region using pyfiglet.
        
        Parameters:
        number (str): The number to print.
        font (str): The pyfiglet font to use.
        color (str): The color to use for the text.
        start_row (int): The starting row for the ASCII art.
        start_col (int): The starting column for the ASCII art.
        """
        color = color or self.current_color  # Use provided text color or fallback to remembered color
        self.current_color = color  # Remember the current text color

        # Generate the ASCII art
        figlet = pyfiglet.Figlet(font=font)
        ascii_art = figlet.renderText(str(number))

        # Split the ASCII art into lines
        lines = ascii_art.splitlines()

        # Determine starting row
        start_row = start_row or self.start_row

        # Print each line in the correct position
        for i, line in enumerate(lines):
            row = start_row + i
            if row > self.stop_row:  # Stop if exceeding the region
                break
            print(color, end="", flush=True)
            print(f"\033[{row};{start_col}H{line}", end="")
            print(Style.RESET_ALL, end="", flush=True)  # Reset style after each line





def ErrorHandler(ErrorMessage='',TraceMessage='',AdditionalInfo=''):
  os.system("stty sane")
  CallingFunction =  inspect.stack()[1][3]
  #FinalCleanup(stdscr)
  print("")
  print("")
  print("--------------------------------------------------------------")
  print("ERROR - Function (",CallingFunction, ") has encountered an error. ")
  print(ErrorMessage)
  print("")
  print("")
  print("TRACE")
  print(TraceMessage)
  print("")
  print("")
  if (AdditionalInfo != ""):
    print("Additonal info:",AdditionalInfo)
    print("")
    print("")
  print("--------------------------------------------------------------")
  print("")
  print("")
  




def identify_packet_type(packet):
    """
    Identifies the type of packet and returns a string indicating the protocol.

    :param packet: Scapy packet object to be analyzed.
    :return: A string representing the identified packet type.
    """

    #HeaderWindow.UpdateLine(1,40,f"Function: {inspect.currentframe().f_code.co_name}        ")

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
        return "UNKNOWN Packet Type"






def PrintConsoleHeader(header_lines, start_row=0, color=Fore.GREEN):
    """
    Prints the lines from a dictionary at a specified starting row in the terminal.
    
    Parameters:
    header_lines: Dictionary with line numbers as keys and strings as values.
    start_row: The row number to begin printing from.
    """
    # Sort the dictionary by keys to ensure the lines are in order
    sorted_lines = [header_lines[key] for key in sorted(header_lines)]
    
    print(color, end="", flush=True)

    # Start printing at the specified row
    for i, line in enumerate(sorted_lines):
        # Move cursor to the appropriate row and column 1
        print(f"\033[{start_row + i};1H{line}", end="")
    
    # Clear any remaining text below the printed lines (optional)
    #print("\033[J", end="")



def profile_decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        profile_function(func.__name__, "start")
        result = func(*args, **kwargs)
        profile_function(func.__name__, "stop")
        return result
    return wrapper



def profile_function(function_name, action):
    global profiling_data
    global profile_lock
    
    with profile_lock:  # Acquire lock before updating coordinates

        if action.lower() == "start":
            # Record the start time for the given function
            
            if function_name not in profiling_data:
                profiling_data[function_name] = {
                    "start_time": None,
                    "total_time": 0,
                    "call_count": 0,
                    "min_time": float('inf'),
                    "max_time": 0,
                }
            profiling_data[function_name]["start_time"] = time.time()

        elif action.lower() == "stop":
            
            # Ensure function has started
            if function_name in profiling_data and profiling_data[function_name]["start_time"] is not None:
                # Calculate elapsed time
                elapsed_time = time.time() - profiling_data[function_name]["start_time"]
                
                # Update stats
                profiling_data[function_name]["total_time"] += elapsed_time
                profiling_data[function_name]["call_count"] += 1
                profiling_data[function_name]["min_time"] = min(profiling_data[function_name]["min_time"], elapsed_time)
                profiling_data[function_name]["max_time"] = max(profiling_data[function_name]["max_time"], elapsed_time)
                
                # Reset the start time
                profiling_data[function_name]["start_time"] = None
            else:
                print(f"Warning: 'stop' called without a matching 'start' for function '{function_name}'")
            


@profile_decorator
def get_profile_summary(top_x=5):
    # Collect profiling data with average times
    functions_with_avg_times = []

    for function_name, data in profiling_data.items():
        if data["call_count"] > 1:
            avg_time = data["total_time"] / data["call_count"]
            functions_with_avg_times.append({
                "function_name": function_name,
                "call_count": data["call_count"],
                "avg_time": avg_time,
                "min_time": data["min_time"],
                "max_time": data["max_time"]
            })

    # Sort the functions by average time in descending order to get the slowest
    functions_with_avg_times.sort(key=lambda x: x["avg_time"], reverse=True)

    # Display the top X slowest functions
    InfoWindow.QueuePrint(f"Top {top_x} Slowest Functions by Average Runtime:\n")
    for i, function_data in enumerate(functions_with_avg_times[:top_x]):
        InfoWindow.QueuePrint(f"{i + 1}. Function: {function_data['function_name']}")
        InfoWindow.QueuePrint(f"   Calls:    {function_data['call_count']}")
        InfoWindow.QueuePrint(f"   Avg Time: {function_data['avg_time']:.2f} seconds")
        InfoWindow.QueuePrint(f"   Min Time: {function_data['min_time']:.2f} seconds")
        InfoWindow.QueuePrint(f"   Max Time: {function_data['max_time']:.2f} seconds\n")
    
    # Optionally, display all the functions in the order of their performance
    # InfoWindow.QueuePrint("\nDetailed profiling summary for all functions:\n")
    # for function_data in functions_with_avg_times:
    #     InfoWindow.QueuePrint(f"Function '{function_data['function_name']}':")
    #     InfoWindow.QueuePrint(f"  Calls: {function_data['call_count']}")
    #     InfoWindow.QueuePrint(f"  Avg Time: {function_data['avg_time']:.4f} seconds")
    #     InfoWindow.QueuePrint(f"  Min Time: {function_data['min_time']:.4f} seconds")
    #     InfoWindow.QueuePrint(f"  Max Time: {function_data['max_time']:.4f} seconds\n")







@profile_decorator
def format_into_columns(max_length, *args):
    """
    Formats a set of variables into columns within a given max length.

    :param data: Base string to be formatted.
    :param max_length: Maximum total length for the formatted output.
    :param args: Values to be formatted into columns.
    :return: A formatted string with each argument fitting within calculated column lengths.
    """
    # Determine how many columns are needed
    column_count = len(args)
    
    if column_count == 0:
        return 'error'
    
    # Calculate available space for each column
    space_for_columns = max_length
    column_width = max(1, space_for_columns // column_count)
    
    # Truncate or pad the arguments to fit within each column's width
    formatted_values = []
    for arg in args:
        str_arg = str(arg)
        if len(str_arg) > column_width:
            formatted_values.append(str_arg[:column_width - 2] )
        else:
            formatted_values.append(str_arg.ljust(column_width))
    
    # Build the final string
    formatted_string = f" ".join(formatted_values)

    

    # Truncate if total length exceeds max_length
    if len(formatted_string) > max_length:
        return formatted_string[:max_length] 

    return formatted_string


@profile_decorator
def replace_none_with_unknown(*args):
    """
    Takes a list of arguments and replaces any None value with "UNKNOWN".
    Returns a list with updated values.
    
    :param args: List of arguments to be checked.
    :return: List of updated arguments with None replaced by "UNKNOWN"
    """
    return ["UNKNOWN" if arg is None else arg for arg in args]



@profile_decorator
def extract_signal_strength(packet):
    """
    Extracts the signal strength (RSSI) from a Wi-Fi packet.
    
    :param packet: Scapy packet object to be analyzed.
    :return: Signal strength in dBm if available, otherwise returns 'UNKNOWN'.
    """
    #HeaderWindow.UpdateLine(1,40,f"Function: {inspect.currentframe().f_code.co_name}        ")


    # Check if the packet has a Dot11 layer, which is used in Wi-Fi packets.
    if packet.haslayer(Dot11):
        # Try to access the dBm_AntSignal attribute which represents the signal strength.
        if hasattr(packet, 'dBm_AntSignal'):
            return packet.dBm_AntSignal

    # If no signal strength information is available, return 'UNKNOWN'.
    return 'UNKNOWN'


@profile_decorator
def get_current_gps_coordinates():
    global latitude
    global longitude
    global gps_lock
    global gps_stop_event

    # Set up the GPS session
    gpsd = gps.gps(mode=gps.WATCH_ENABLE)  # Enable the streaming mode for GPS data

    try:
        # Wait until we receive GPS data with valid lat and lon
        while not gps_stop_event.is_set():
            gpsd.next()  # Get the next set of GPS data
            if gpsd.fix.mode >= 2:  # Ensure we have a valid GPS fix (2D or 3D)
                with gps_lock:  # Acquire lock before updating coordinates
                    latitude = str(gpsd.fix.latitude)
                    longitude = str(gpsd.fix.longitude)
                
                # Add a delay between GPS reads to avoid busy waiting
                time.sleep(gps_interval)  # Adjust as needed for acceptable update frequency
    except Exception as e:
        InfoWindow.QueuePrint(f"Error in GPS Thread: {e}")
        




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




@profile_decorator
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




@profile_decorator
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


@profile_decorator
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


@profile_decorator
def get_vendor(mac, oui_dict):

    #HeaderWindow.UpdateLine(1,40,f"Function: {inspect.currentframe().f_code.co_name}        ")

    # Extract the OUI prefix (first 8 characters)
    mac_prefix = normalize_mac(mac[:8])  # Normalize delimiter format
    InfoWindow.QueuePrint(f"Looking up MAC Prefix: {mac_prefix}")

    # Check if the OUI prefix is already in the cache
    if mac_prefix in vendor_cache:
        InfoWindow.QueuePrint(f"Cache Hit for {mac_prefix}")
        return vendor_cache[mac_prefix]

    # Lookup in the OUI dictionary
    if mac_prefix in oui_dict:
        vendor_info = oui_dict[mac_prefix]
        InfoWindow.QueuePrint(f"Vendor Found: {vendor_info}")
    else:
        # Fallback: Use netaddr to try and fetch vendor info if not in oui_dict
        try:
            MAC = netaddr.EUI(mac)
            vendor_info = (MAC.oui.registration().org, "No Long Description Available")
            InfoWindow.QueuePrint(f"Fallback Vendor Info from netaddr: {vendor_info}")
        except (netaddr.core.NotRegisteredError, ValueError):
            vendor_info = ("UNKNOWN", "UNKNOWN")
            InfoWindow.QueuePrint(f"Vendor Not Found for {mac_prefix}")

    # Store the found result in the vendor_cache for future lookups
    vendor_cache[mac_prefix] = vendor_info
    return vendor_info





'''
    try:
        MAC = netaddr.EUI(mac)
        vendor = MAC.oui.registration().org
    except netaddr.core.NotRegisteredError:
        vendor = 'UNKNOWN or Not Registered'
    except ValueError:
        vendor = 'UNKNOWN'

    # Cache the OUI result
    vendor_cache[mac_prefix] = vendor
    return vendor
'''

@profile_decorator
def extract_ssid(packet):
    #Extracts SSID from a packet if present.
    try:
        if packet.haslayer(Dot11Elt) and isinstance(packet[Dot11Elt].info, bytes):
            return packet[Dot11Elt].info.decode('utf-8', errors='ignore')
    except Exception as e:
        return 'UNKNOWN'
    return 'UNKNOWN'



@profile_decorator
def load_friendly_devices_dict(filename):
    with open(filename, 'r') as json_file:
        return json.load(json_file)

@profile_decorator
def load_oui_dict_from_json(filename):
    with open(filename, 'r') as json_file:
        return json.load(json_file)



# Example Lookup Function
@profile_decorator
def lookup_vendor_by_mac(mac, oui_dict):
    ## Extract and normalize the OUI prefix from MAC address
    mac_prefix = normalize_mac(mac[:8])
    return oui_dict.get(mac_prefix, ("UNKNOWN", "UNKNOWN"))




@profile_decorator
def determine_device_type(oui):
  device_type = device_type_dict.get(oui, "UNKNOWN")
  return device_type 


@profile_decorator
def determine_device_type_with_packet(packet):
    """
    Determines the likely type of the device that sent the given packet.
    
    Device types are inferred based on packet behavior, known vendors, SSID, or
    specific network activity.
    
    :param packet: Scapy packet object to analyze.
    :return: String indicating the likely device type.
    """
    #HeaderWindow.UpdateLine(1,40,f"Function: {inspect.currentframe().f_code.co_name}        ")

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
                return "UNKNOWN (" + vendor_name.title() + ")"

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

    # Fallback to UNKNOWN Device
    return "UNKNOWN Device"










# Function to search for a MAC address in a list of friendly devices
@profile_decorator
def search_friendly_devices(mac, friendly_devices):

    for device in friendly_devices:
        if device["MAC"] == mac:
            return {"FriendlyName": device["FriendlyName"], "Type": device["Type"], "Brand": device["Brand"]}

    return None  # Return None if MAC is not found



#-------------------------------
#-- Database Reports
#-------------------------------

def ProduceReport_TopDevices(TheCount) :
      global DetailsWindow
      global InfoWindow

      result = GetTopDevices(TheCount)
      log_message(" ",DetailsWindow)
      title = f"{'FriendlyName':<20} {'SourceMAC':<17} {'DeviceType':<30} {'SSID':<25}      {'Frequency':>10}"

      if curses_enabled:
        log_message(" ",DetailsWindow)
        log_message("TOP DEVICES REPORT",DetailsWindow,color=Fore.YELLOW)
        log_message(title,DetailsWindow,color=Fore.YELLOW)
      else:
        console_region.print_large(f"TOP {TheCount} DEVICES TODAY                                   ", font="pagga", color=Fore.YELLOW, start_row=console_region.current_row,  start_col=1)
        console_region.current_row += 3
        console_region.region_print_line(title,regular_color=Fore.YELLOW)
  
      for friendly_name, source_mac, device_type, ssid, frequency in result:
        output = (f"{friendly_name[:20]:<20} {source_mac:<17} {device_type[:30]:<30} {ssid[:25]:<25}{frequency:>10}")    
        log_message(output,DetailsWindow,color=Fore.YELLOW)

      log_message(" ",DetailsWindow)


def GetTopDevices(top_x: int) -> List[Tuple[str, int]]:
    global DBReports

    query = f'''
    SELECT COALESCE(FriendlyName,'??') as FriendlyName, 
           SourceMAC, DeviceType, SSID, COUNT(*) as Frequency
    FROM Packet
    WHERE CaptureDate >= datetime('now', '-24 hours')
    GROUP BY SourceMAC
    ORDER BY Frequency DESC
    LIMIT ?;
    '''

    try:
        # Connect to the SQLite database
        DBReports = sqlite3.connect(PacketDB)
        cursor    = DBReports.cursor()

        # Execute the query with the provided limit
        cursor.execute(query, (top_x,))

        # Fetch all results
        results = cursor.fetchall()

        # Close the connection
        DBReports.close()

        return results

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return []








def ProduceReport_TopMobile(TheCount) :
      global DetailsWindow
      global InfoWindow

      result = GetTopMobile(TheCount)
      log_message(" ",DetailsWindow)
      title = f"{'FriendlyName':<20} {'SourceMAC':<17} {'DeviceType':<30} {'SSID':<25}      {'Frequency':>10}"

      if curses_enabled:
        log_message(" ",DetailsWindow)
        log_message("TOP MOBILE REPORT",DetailsWindow,color=Fore.YELLOW)
        log_message(title,DetailsWindow,color=Fore.YELLOW)
      else:
        console_region.print_large(f"TOP {TheCount} MOBILE DEVICES TODAY                            ", font="pagga", color=Fore.YELLOW, start_row=console_region.current_row,  start_col=1)
        console_region.current_row += 3
        console_region.region_print_line(title,regular_color=Fore.LIGHTYELLOW_EX)
  
      for friendly_name, source_mac, device_type, ssid, frequency in result:
        output = (f"{friendly_name[:20]:<20} {source_mac:<17} {device_type[:30]:<30} {ssid[:25]:<25}{frequency:>10}")    
        log_message(output,DetailsWindow,color=Fore.YELLOW)

      log_message(" ",DetailsWindow)


def GetTopMobile(top_x: int) -> List[Tuple[str, int]]:
    """
    Query the SQLite database to return the top X most frequent mobile devices

    Args:
        database_path (str): Path to the SQLite database.
        top_x (int): Number of top frequent records to retrieve.

    Returns:
        List[Tuple[str, int]]: A list of tuples containing SourceMAC and their frequency.
    """

    global DBReports

    query = f'''
    SELECT COALESCE(FriendlyName,'??') as FriendlyName, 
           SourceMAC, DeviceType, SSID, COUNT(*) as Frequency
    FROM Packet
    WHERE CaptureDate >= datetime('now', '-24 hours')
      AND PacketType like '%mobile%'
    GROUP BY SourceMAC
    ORDER BY Frequency DESC
    LIMIT ?;
    '''
    


    try:
        # Connect to the SQLite database
        DBReports = sqlite3.connect(PacketDB)
        cursor    = DBReports.cursor()

        # Execute the query with the provided limit
        cursor.execute(query, (top_x,))

        # Fetch all results
        results = cursor.fetchall()

        # Close the connection
        DBReports.close()

        return results

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return []





def ProduceReport_RecentIntruders(TheCount) :
      global DetailsWindow
      global InfoWindow

      result = GetRecentIntruders(TheCount)
      log_message(" ",DetailsWindow)
      title = f"{'SourceMAC':<17} {'DeviceType':<30} {'SSID':<25}      {'Frequency':>10}"

      if curses_enabled:
        log_message(" ",DetailsWindow)
        log_message("RECENT INTRUDERS REPORT",DetailsWindow)
        log_message(title,DetailsWindow,color=Fore.YELLOW)
      else:
        console_region.print_large(f"TOP {TheCount} RECENT INTRUDERS TODAY               ", font="pagga", color=Fore.YELLOW, start_row=console_region.current_row,  start_col=1)
        console_region.current_row += 3
        console_region.region_print_line(title,regular_color=Fore.LIGHTYELLOW_EX)
  
      for source_mac, device_type, ssid, frequency in result:
        output = (f"{source_mac:<17} {device_type[:30]:<30} {ssid[:25]:<25}{frequency:>10}")    
        log_message(output,DetailsWindow,color=Fore.YELLOW)

      log_message(" ",DetailsWindow)





def GetRecentIntruders(top_x: int) -> List[Tuple[str, int]]:
    global DBReports

    query = f'''
    SELECT coalesce(SourceMAC,'??')  as SourceMAC, 
           coalesce(DeviceType,'??') as DeviceType, 
           coalesce(SSID,'??')       as SSID, 
           COUNT(*) as Frequency
    FROM Packet
    WHERE CaptureDate >= datetime('now', '-24 hours')
      AND FriendlyName is NULL or FriendlyName = ''
    GROUP BY SourceMAC
    ORDER BY Frequency DESC
    LIMIT ?;
    '''

    try:
        # Connect to the SQLite database
        DBReports = sqlite3.connect(PacketDB)
        cursor    = DBReports.cursor()

        # Execute the query with the provided limit
        cursor.execute(query, (top_x,))

        # Fetch all results
        results = cursor.fetchall()

        # Close the connection
        DBReports.close()

        return results

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return []








#-------------------------------
#-- Database Functions
#-------------------------------



@profile_decorator
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
        cursor = DBConnection.cursor()


        # Define SQL statement to insert packet data
        insert_query = '''
        INSERT INTO Packet (
            FriendlyName, FriendlyType, PacketType, DeviceType, 
            SourceMAC, SourceVendor, DestMAC, DestVendor, 
            SSID, Band, Channel, Latitude, Longitude, Signal
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
            DBPacket.get('Channel'),
            DBPacket.get('Longitude'),
            DBPacket.get('Latitude'),
            DBPacket.get('Signal')
        ))

        # Commit the changes 
        DBConnection.commit()
        #InfoWindow.QueuePrint("Connection Closed")

        
        #print("Packet data inserted successfully.")
    except sqlite3.Error as e:
        InfoWindow.QueuePrint(f"SQLite error: {e}")
    #finally:
        # Ensure the connection is closed
        #conn.close()
        #print("Insert operation complete.")












#-------------------------------
#-- Packet Callback 
#-------------------------------

@profile_decorator
def packet_callback(packet):
    try:

        # Add packet to the queues for processing and saving by other threads
        PacketQueue.put(packet)
        
       
    except Exception as e:
        TraceMessage = traceback.format_exc()
        if curses_enabled:
          InfoWindow.ErrorHandler(str(e), TraceMessage, "**Error in packet callback**")
        else:
          ErrorHandler(TraceMessage)


@profile_decorator
def process_PacketQueue():
    global InfoWindow
    global ProcessedPacket

    ProcessedPacket = PacketInformation()
    DisplayHeader()
    
    while True:
        try:

            #Initialize and empty packet to store processed information
            ProcessedPacket = PacketInformation()

            #Display Header info
            if PacketCount % HeaderUpdateSpeed == 0:
              DisplayHeader()
            
            # Retrieve a packet from the queue (wait indefinitely if empty)
            packet = PacketQueue.get()


            #Take the packet and extract data from it, storing it in a special object
            ProcessedPacket = process_packet(packet)

            #take the special object and save to database, print to screen, etc.
            if ProcessedPacket:
              ProcessPacketInfo()

            # Signal that processing of this item is done
            PacketQueue.task_done()

        except Exception as e:
            # Use the current thread's name to improve diagnostics
            thread_name  = threading.current_thread().name
            TraceMessage = traceback.format_exc()
            if curses_enabled:
              InfoWindow.ErrorHandler(f"[{thread_name}] {str(e)}", TraceMessage, "Error in packet processing thread")
            else:
              ErrorHandler(thread_name,TraceMessage)


@profile_decorator
def process_DBQueue():
    global InfoWindow
    global DBQueue
    global PacketsSavedToDBCount
    global PacketDB
    global DBConnection

    #Database connections
    log_message("Establishing SQLite connection",ShowTime=True)
    DBConnection = sqlite3.connect(PacketDB)
    log_message("Database connection established.",ShowTime=True)


    while True:
        try:
            # Retrieve a packet from the DBqueue (wait indefinitely if empty)
            DBpacket = DBQueue.get()
            #InfoWindow.QueuePrint("Got a packet from the DBQueue")

            save_DB_Packet(DBpacket)
            PacketsSavedToDBCount = PacketsSavedToDBCount + 1
            # Signal that processing of this item is done
            DBQueue.task_done()

        except Exception as e:
            # Use the current thread's name to improve diagnostics
            thread_name = threading.current_thread().name
            TraceMessage = traceback.format_exc()
            if curses_enabled:
              InfoWindow.ErrorHandler(f"[{thread_name}] {str(e)}", TraceMessage, "Error in DBQueue processing thread")
            else:
              ErrorHandler(TraceMessage)
            



#------------------------------------
#-- Process Packet and Display Info
#------------------------------------

@profile_decorator
def process_packet(packet):
    
    global HeaderWindow
    global PacketWindow
    global InfoWindow
    global DetailsWindow
    global RawWindow
    global oui_dict
    global friendly_devices_dict
    global current_channel_info
    global displayed_packets_cache
    global friendly_device_cache
    global key_count
    global PacketCount
    global friendly_key_count
    global DBQueue
    global PacketsSavedToDBCount
    global gps_lock
    global console_region
    global ProcessedPacket
    global MobileCount
    global RouterCount
    global DeviceTypeDict

    ProcessedPacket = PacketInformation()

    
    PacketCount   = PacketCount + 1
 

    def resolve_mac(mac, resolver_function, packet):
        #HeaderWindow.UpdateLine(1,40,f"Function: {inspect.currentframe().f_code.co_name}        ")
        if 'UNKNOWN' in mac.upper():
            return resolver_function(packet)
        
        return mac

    
    #HeaderWindow.UpdateLine(1,40,f"Function: {inspect.currentframe().f_code.co_name}")


    #-------------------------------
    #-- Get all packet information
    #-------------------------------

    try:
      
      #Get all the information about the packet before displaying anything
      ProcessedPacket.PacketType     = identify_packet_type(packet)
      ProcessedPacket.packet_layers  = identify_packet_layers(packet)
        
      #Convert packet to a string for displaying
      ProcessedPacket.packet_info    = packet.show(dump=True)
      ProcessedPacket.packet_details = get_packet_details_as_string(packet)

      

      #There can be more than one source/destination depending on the type of packet
      #We will focus on WIFI packets for this project
      ProcessedPacket.mac_details   = extract_oui_and_vendor_information(packet)

      #RawWindow.QueuePrint(f"==========================================")
      #RawWindow.QueuePrint(f"mac_details: {mac_details}")
      
      # Iterate through each key-value pair in the mac_info dictionary
      #InfoWindow.QueuePrint("-----MAC DETAILS-------------------------------")
      

      

      if ProcessedPacket.mac_details != None:
        # Iterate through each key-value pair in the mac_details dictionary
        for mac_type, details in ProcessedPacket.mac_details.items():
            # Check if the current type indicates a source MAC
            #InfoWindow.QueuePrint(f"mac_type: {mac_type}")

            if 'SOURCE' in mac_type.upper():
                # Extract the MAC address and normalize it
                ProcessedPacket.source_mac = normalize_mac(details.get('MAC', 'UNKNOWN'))
                    
                # Check if the source MAC is valid
                if ProcessedPacket.source_mac != 'UNKNOWN' and ProcessedPacket.source_mac is not None:
                    # Log the found source MAC and stop processing
                    #InfoWindow.QueuePrint(f"Found valid source_mac: {source_mac}")
                    ProcessedPacket.source_vendor = details.get('Vendor', 'UNKNOWN')
                    #InfoWindow.QueuePrint(f"Vendor: {source_vendor}")
                    break  # Exit the loop once the first valid source MAC is found

            # Optionally handle destination MACs or other details
            if 'DEST' in mac_type.upper():
                dest_mac = normalize_mac(details.get('MAC', 'UNKNOWN'))
                ProcessedPacket.dest_vendor = details.get('Vendor', 'UNKNOWN')


      if ProcessedPacket.source_mac != 'UNKNOWN' and ProcessedPacket.source_mac != None:
          ProcessedPacket.source_mac = resolve_mac(ProcessedPacket.source_mac, get_source_mac, packet)
      
      if ProcessedPacket.dest_mac != 'UNKNOWN' and ProcessedPacket.dest_mac != None:
        ProcessedPacket.dest_mac   = resolve_mac(ProcessedPacket.dest_mac, get_destination_mac, packet)

      if ProcessedPacket.source_mac == 'UNKNOWN' or ProcessedPacket.source_mac == None:
        ProcessedPacket.source_mac == 'FF:FF:FF:FF:FF:FF'
      
      if ProcessedPacket.dest_mac == 'UNKNOWN' or ProcessedPacket.dest_mac == None:
        ProcessedPacket.dest_mac == 'FF:FF:FF:FF:FF:FF'



      # Extract OUI if source_mac is known
      if ProcessedPacket.source_mac != 'UNKNOWN' and ProcessedPacket.source_mac != None:
          ProcessedPacket.source_oui = ProcessedPacket.source_mac[:8]

      ProcessedPacket.ssid    = extract_ssid(packet)
      ProcessedPacket.channel = current_channel_info['channel']
      ProcessedPacket.band    = current_channel_info['band']
      
      #DetailsWindow.UpdateLine(0,1,f"Band: {band} Channel: {str(channel).ljust(5)}")
      #HeaderWindow.UpdateLine(1,1,f"Packets: {PacketCount}")


      # Step 1: Try to determine device type using source OUI if it's available
      if ProcessedPacket.source_oui is not None:
          ProcessedPacket.DeviceType  = determine_device_type(ProcessedPacket.source_oui)

      # Step 2: If device type is still UNKNOWN, try another method using the packet
      if ProcessedPacket.DeviceType  == 'UNKNOWN':
          ProcessedPacket.DeviceType  = determine_device_type_with_packet(packet)

      # Step 3: As a final fallback, if packet type suggests it's a mobile device, mark it as 'Mobile'
      if ProcessedPacket.DeviceType  == 'UNKNOWN' and 'MOBILE' in PacketType.upper():
          ProcessedPacket.DeviceType  = 'Mobile'

      #If we don't want to see routers/access points, exit at this point
      if (show_routers == False) and ('ROUTER' in ProcessedPacket.DeviceType.upper() or 'ACCESS' in ProcessedPacket.DeviceType.upper()):
        return


      #Get the signal strength
      ProcessedPacket.signal = extract_signal_strength(packet)



      #Keep track of devices by type
      DeviceTypeDict[ProcessedPacket.DeviceType].add(ProcessedPacket.source_mac)
      



    except Exception as ErrorMessage:
      TraceMessage   = traceback.format_exc()
      AdditionalInfo = f"Processing Packet: {format_packet(packet)}"

      if curses_enabled:
        InfoWindow.QueuePrint(TraceMessage)
        InfoWindow.QueuePrint(PrintLine=ErrorMessage)
        InfoWindow.ErrorHandler(ErrorMessage,TraceMessage,AdditionalInfo)
        InfoWindow.QueuePrint(f"Error parsing packet: {ErrorMessage}")
      else:
        ErrorHandler(TraceMessage,AdditionalInfo)


    return ProcessedPacket








# Function to set the channel on a given Wi-Fi interface
@profile_decorator
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
            #InfoWindow.QueuePrint(f"Channel: {channel}",Color=6)
        else:
            InfoWindow.QueuePrint(f"Failed to set channel. Error: {result.stderr}",Color=6)
            return -1
    except Exception as e:
        InfoWindow.QueuePrint(f"Error occurred while trying to set channel: {str(e)}",Color=6)

    


#def log_packet(source_mac, vendor, packet_type, ssid=None):
#    with open("packet_log.csv", "a") as log_file:
#        log_writer = csv.writer(log_file)
#        # Use datetime.now() from datetime module to get current timestamp
#        log_writer.writerow([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source_mac, vendor, packet_type, ssid])




















@profile_decorator
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












@profile_decorator
def sniff_packets(interface):
    """
    Sniffs packets on the given interface.
    :param interface: Name of the Wi-Fi interface in monitor mode
    """
    global PacketWindow
    global InfoWindow
    global DetailsWindow
        

    try:
        #InfoWindow.QueuePrint(PrintLine='Sniffing Packets')
        # Sniff packets continuously and send them to packet_callback for processing
        sniff(iface=interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        InfoWindow.QueuePrint(PrintLine='Stopping...')
    except Exception as ErrorMessage:
        TraceMessage   = traceback.format_exc()
        InfoWindow.ErrorHandler(ErrorMessage,TraceMessage,'Error in sniff_packets function')


@profile_decorator
def format_packet(packet):
    """
    Formats a packet for output as a string.
    :param packet: Packet to format
    :return: Formatted string representation of the packet
    """
    try:
        summary = packet.summary()
        if packet.haslayer(Dot11):
            source_mac = normalize_mac(packet[Dot11].addr2)   or "UNKNOWN"
            dest_mac   = normalize_mac(packet[Dot11].addr1)   or "UNKNOWN"
            formatted_string = f"[Source: {source_mac:<17}] [Destination: {dest_mac:<17}] - {summary}"
        else:
            formatted_string = summary
        return formatted_string.expandtabs(4)
    except Exception as e:
        return f"Error formatting packet: {e}"




def normalize_mac(mac: str) -> str:
    return mac.upper().replace('-', ':')


@profile_decorator
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
                'Source MAC': dot11.addr2 if dot11.addr2 else 'UNKNOWN',
                'Destination MAC': dot11.addr1 if dot11.addr1 else 'UNKNOWN',
                'BSSID': dot11.addr3 if dot11.addr3 else 'UNKNOWN',
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
                ssid = packet[Dot11Elt].info.decode('utf-8', 'ignore') if packet.haslayer(Dot11Elt) else 'UNKNOWN'
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
            packet_details['type'] = 'UNKNOWN'
            packet_details['fields'] = {'Raw Data': packet.summary()}

        # Format the packet details for display
        #InfoWindow.QueuePrint(f"Packet Type: {packet_details['type']}")
        #for key, value in packet_details['fields'].items():
        #    InfoWindow.QueuePrint(f"{key}: {value}")

    except Exception as e:
        InfoWindow.QueuePrint(f"Error analyzing packet: {e}")
        traceback.print_exc()




@profile_decorator
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
                log_message(f"Monitoring interface: {iface}",ShowTime=True)
                return iface

    except subprocess.CalledProcessError as e:
        print(f"Error retrieving interface information: {e}")

    return None














@profile_decorator
def extract_oui_and_vendor_information(packet):
    """
    Extracts OUI and vendor information for all possible MAC addresses in the packet.
    
    :param packet: Scapy packet object to be analyzed.
    :return: A dictionary of MAC addresses, OUI, and corresponding vendor information.
    """
    #HeaderWindow.UpdateLine(1,40,f"Function: {inspect.currentframe().f_code.co_name}        ")

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
            return 'UNKNOWN', 'UNKNOWN'
        except ValueError:
            return 'UNKNOWN', 'UNKNOWN'

        try:
            vendor_cache[mac_prefix] = vendor

            if mac_prefix not in oui_dict:
                oui_dict[mac_prefix] = (vendor, "No Long Description Available")

                # Write to file only if we found the vendor by doing the network lookup
                if "UNKNOWN" not in vendor.upper():
                    # Use a lock to prevent concurrent write access
                    with write_lock:
                        with open("oui_dict.json", 'w') as json_file:
                            json.dump(oui_dict, json_file, indent=4)
                            InfoWindow.QueuePrint("Updating OUI master file")

                    InfoWindow.QueuePrint(f"Updated OUI master file: {mac_prefix} - {vendor}", Color=5)
        except Exception as e:
            #InfoWindow.QueuePrint(" ")
            #InfoWindow.QueuePrint(" ")
            #InfoWindow.QueuePrint(f"Error: {e}")
            return 'UNKNOWN', 'UNKNOWN'

        #RawWindow.QueuePrint(packet, Color=1)
        return mac_prefix, vendor

    # Extract MAC addresses from various layers and retrieve their OUI and vendor info

    try:

        # Ethernet Layer
        if packet.haslayer(Ether):
            if hasattr(packet[Ether], 'src'):
                src_mac = normalize_mac(packet[Ether].src)
                if src_mac:
                    src_oui, src_vendor = get_vendor_and_oui(src_mac)
                    mac_info['Ethernet Source MAC'] = {'MAC': src_mac, 'OUI': src_oui, 'Vendor': src_vendor}

            if hasattr(packet[Ether], 'dst'):
                dst_mac = normalize_mac(packet[Ether].dst)
                if dst_mac:
                    dst_oui, dst_vendor = get_vendor_and_oui(dst_mac)
                    mac_info['Ethernet Destination MAC'] = {'MAC': dst_mac, 'OUI': dst_oui, 'Vendor': dst_vendor}

        # ARP Layer
        if packet.haslayer(ARP):
            if hasattr(packet[ARP], 'hwsrc'):
                src_mac = normalize_mac(packet[ARP].hwsrc)
                if src_mac:
                    src_oui, src_vendor = get_vendor_and_oui(src_mac)
                    mac_info['ARP Source MAC'] = {'MAC': src_mac, 'OUI': src_oui, 'Vendor': src_vendor}

            if hasattr(packet[ARP], 'hwdst'):
                dst_mac = normalize_mac(packet[ARP].hwdst)
                if dst_mac:
                    dst_oui, dst_vendor = get_vendor_and_oui(dst_mac)
                    mac_info['ARP Destination MAC'] = {'MAC': dst_mac, 'OUI': dst_oui, 'Vendor': dst_vendor}

        # 802.11 Wireless Layer
        if packet.haslayer(Dot11):
            # Destination MAC
            if hasattr(packet, 'addr1') and packet.addr1:
                dst_mac = normalize_mac(packet.addr1)
                if dst_mac:
                    dst_oui, dst_vendor = get_vendor_and_oui(dst_mac)
                    mac_info['WIFI Destination MAC'] = {'MAC': dst_mac, 'OUI': dst_oui, 'Vendor': dst_vendor}

            # Source MAC
            if hasattr(packet, 'addr2') and packet.addr2:
                src_mac = normalize_mac(packet.addr2)
                if src_mac:
                    src_oui, src_vendor = get_vendor_and_oui(src_mac)
                    mac_info['WIFI Source MAC'] = {'MAC': src_mac, 'OUI': src_oui, 'Vendor': src_vendor}

            # BSSID
            if hasattr(packet, 'addr3') and packet.addr3:
                bssid_mac = normalize_mac(packet.addr3)
                if bssid_mac:
                    bssid_oui, bssid_vendor = get_vendor_and_oui(bssid_mac)
                    mac_info['WIFI BSSID'] = {'MAC': bssid_mac, 'OUI': bssid_oui, 'Vendor': bssid_vendor}

            # Additional MAC Address (usually used in WDS frames)
            if hasattr(packet, 'addr4') and packet.addr4:
                additional_mac = normalize_mac(packet.addr4)
                if additional_mac:
                    additional_oui, additional_vendor = get_vendor_and_oui(additional_mac)
                    mac_info['WIFI Additional MAC'] = {'MAC': additional_mac, 'OUI': additional_oui, 'Vendor': additional_vendor}

        # VLAN Tagged Frame Layer
        if packet.haslayer(Dot1Q):
            if hasattr(packet[Dot1Q], 'src'):
                src_mac = normalize_mac(packet[Dot1Q].src)
                if src_mac:
                    src_oui, src_vendor = get_vendor_and_oui(src_mac)
                    mac_info['VLAN Tagged MAC'] = {'MAC': src_mac, 'OUI': src_oui, 'Vendor': src_vendor}

        # 802.3 Layer (for LLC Ethernet packets)
        if packet.haslayer(Dot3):
            if hasattr(packet[Dot3], 'src'):
                src_mac = normalize_mac(packet[Dot3].src)
                if src_mac:
                    src_oui, src_vendor = get_vendor_and_oui(src_mac)
                    mac_info['802.3 Source MAC'] = {'MAC': src_mac, 'OUI': src_oui, 'Vendor': src_vendor}
    except Exception as e:
        #InfoWindow.QueuePrint("zzzzzzzzzzzzzzzzzzzzzz ")
        #InfoWindow.QueuePrint(" ")
        #InfoWindow.QueuePrint(f"Error: {e}")
        mac_info = None
        return mac_info

    
    return mac_info


@profile_decorator
def identify_packet_layers(packet):
    """
    Identifies all the layers present in the packet and returns a list of protocol names.

    :param packet: Scapy packet object to be analyzed.
    :return: A list of strings representing the identified layers.
    """
    #HeaderWindow.UpdateLine(1,40,f"Function: {inspect.currentframe().f_code.co_name}        ")

    layers = []

    # Use a while loop to iterate through all layers
    current_layer = packet
    while current_layer:
        # Append the name of the current layer's class to the list
        layers.append(current_layer.__class__.__name__)
        # Move to the next layer (payload) in the packet
        current_layer = current_layer.payload

    # If no known layers found, append "UNKNOWN Layer"
    if not layers:
        layers.append("UNKNOWN Layer")

    return layers



   






@profile_decorator
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

    # Total number of entries
    total_entries = len(oui_dict)

    # Count occurrences of vendors in the OUI dictionary
    vendor_counter = Counter()

    # Number of unique vendors
    total_unique_vendors = len(vendor_counter)

    # Vendors with multiple OUIs
    vendors_with_multiple_ouis = {vendor: count for vendor, count in vendor_counter.items() if count > 1}


    if curses_enabled:
        InfoWindow.QueuePrint("=== OUI Dictionary Statistics ===")
        InfoWindow.QueuePrint(f"Total Number of OUI Entries:    {total_entries}")
        for oui, (short_desc, long_desc) in oui_dict.items():
            vendor_counter[short_desc] += 1
        InfoWindow.QueuePrint(f"Total Number of Unique Vendors: {total_unique_vendors}")
        InfoWindow.QueuePrint(f"Vendors with Multiple OUIs:     {len(vendors_with_multiple_ouis)}")

        # Print top vendors with the most OUI entries
        InfoWindow.QueuePrint("Top 25 Vendors with the Most OUI Entries:")
        for vendor, count in vendor_counter.most_common(25):
            InfoWindow.QueuePrint(f"Vendor:  {vendor}")
            InfoWindow.QueuePrint(f"Entries: {count}")

    else:
        print(Fore.YELLOW,end="", flush=True)
        print(pyfiglet.figlet_format("       OUI Dictionary       ", font='pagga',width=console_width))
        #print("=== OUI Dictionary Statistics ===")
        print(f"Total Number of OUI Entries:    {total_entries}")
        for oui, (short_desc, long_desc) in oui_dict.items():
            vendor_counter[short_desc] += 1
        print(f"Total Number of Unique Vendors: {total_unique_vendors}")
        print(f"Vendors with Multiple OUIs:     {len(vendors_with_multiple_ouis)}")

        # Print top vendors with the most OUI entries
        print("Top 10 Vendors with the Most OUI Entries:")
        for vendor, count in vendor_counter.most_common(10):
            print(f"Vendor:  {vendor}")
            print(f"Entries: {count}")
        print(pyfiglet.figlet_format("                             ", font='pagga',width=console_width))
      





###########################################################
#  MAIN PROCESSING                                        #
###########################################################

@profile_decorator
def channel_hopper(interface, hop_interval, max_retries=3):
    global current_channel_info

    band = None

    # Define available channels for 2.4 GHz and 5 GHz
    #channels_24ghz = list(range(1, 14))  # Channels 1 to 13 for 2.4 GHz
    channels_24ghz = [
        1,2,3,4,5,6,7,8,9,10,11
    ]
    
    # Master list of 5GHz channels
    channels_5ghz = [
        36, 40, 44, 48, 
        52, 56, 60, 64, 
        100, 104, 108, 112, 116,  
        132, 136, 140, 144,
        149, 153, 157, 161, 165
    ]

    # Combine all channels into one list
    all_channels = channels_24ghz + channels_5ghz
    disabled_channels = set()  # Keep track of disabled channels
    channel_index = 0

    try:
        while True:
            # Get the current channel to attempt setting
            current_channel = all_channels[channel_index]
            
            # Skip channel if it has been marked as disabled
            if current_channel in disabled_channels:
                #InfoWindow.QueuePrint(f"Skipping previously disabled channel {current_channel}", Color=3)
                channel_index = (channel_index + 1) % len(all_channels)
                continue

            # Attempt to set the channel, retrying up to max_retries
            retries = 0
            channel_result = -1
            while retries < max_retries:
                channel_result = set_channel(interface, current_channel)
                if channel_result == 0:
                    # Successfully set the channel, break the retry loop
                    break
                else:
                    #InfoWindow.QueuePrint(f"Failed to set channel {current_channel}, retry {retries + 1}/{max_retries}", Color=3)
                    retries += 1

            # If max retries are reached, mark the channel as disabled
            if retries == max_retries:
                #InfoWindow.QueuePrint(f"Max retries reached for channel {current_channel}, marking it as disabled.", Color=1)
                disabled_channels.add(current_channel)

            # If the channel was successfully set, update current channel info
            if channel_result == 0:
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
                # Wait for the specified hop interval before switching channels again
                #InfoWindow.QueuePrint(f"Successfully set to {current_channel_info['band']} - Channel {current_channel} - Freq. {current_channel_info['frequency']} MHz", Color=5)
                
                band = current_channel_info["band"]
                
                
                # 2.4 has more traffic so we will hopt through the 5Ghz channels faster
                if band == '2.4 GHz':
                  time.sleep(hop_interval)
                else:
                  time.sleep(hop_interval/hop_modifier)

            # Move to the next channel (wrap around if at the end)
            channel_index = (channel_index + 1) % len(all_channels)

            

    except KeyboardInterrupt:
        InfoWindow.QueuePrint("Channel hopping stopped by user.")



@profile_decorator
def log_active_threads():
    """
    Logs detailed information about all active threads.
    """
    all_threads = threading.enumerate()
    InfoWindow.QueuePrint("=== Active Thread Report ===", Color=5)
    InfoWindow.QueuePrint(f"Total Active Threads: {len(all_threads)}", Color=5)

    for thread in all_threads:
        # Gathering detailed information for each thread
        thread_name = thread.name
        thread_ident = thread.ident
        is_alive = thread.is_alive()
        is_daemon = thread.daemon
        stack_size = threading.stack_size()

        # Preparing the log message
        
        InfoWindow.QueuePrint(f"Thread Name    : {thread_name}",Color=3)
        InfoWindow.QueuePrint(f"Thread ID      : {thread_ident}",Color=3)
        InfoWindow.QueuePrint(f"Is Alive       : {'Yes' if is_alive else 'No'}",Color=3)
        InfoWindow.QueuePrint(f"Is Daemon      : {'Yes' if is_daemon else 'No'}",Color=3)
        InfoWindow.QueuePrint(f"Stack Size     : {stack_size} bytes",Color=3)
        InfoWindow.QueuePrint(f"--------------------------------------",Color=3)
       


def periodic_thread_logging(interval=60):
    while True:
        log_active_threads()
        time.sleep(interval)




# Integrate channel hopping in the main function
def main(stdscr):
    global HeaderWindow
    global PacketWindow
    global InfoWindow
    global DetailsWindow
    global RawWindow
    global oui_dict
    global friendly_devices_dict
    global hop_interval
    global PacketDB
    global DBConnection
    global DBReports
    global Latitude
    global Longitude
    global current_latitude
    global current_longitude
    global gps_stop_event
    global curses_enabled
    global console_region
    global console_width
    global console_height
    global last_time
    global ProcessedPacket
    
       

    #--------------------------------------
    #-- Setup text windows 
    #--------------------------------------


    if curses_enabled:

        # Call the helper function to initialize curses
        textwindows.initialize_curses(stdscr)

        # Calculate window sizes for display
        ScreenHeight, ScreenWidth = textwindows.get_screen_dimensions(stdscr)
        max_y, max_x = stdscr.getmaxyx()

        if ScreenWidthOverride > 0:
            max_x = ScreenWidthOverride
        window_width = max_x // HorizontalWidthUnits

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
            (10, ""),
            (11, ""),
            (12, ""),
        ]
    
        HeaderWindow  = textwindows.HeaderWindow(name='HeaderWindow', title='Header',    rows= HeaderHeight, columns=window_width *2, y1=0, x1=0,                                 ShowBorder='Y', BorderColor=2, TitleColor=3,fixed_lines=fixed_lines)
        DetailsWindow = textwindows.TextWindow  (name='DetailsWindow',title='Details',   rows=max_y - 1,     columns=window_width *3, y1=(HeaderHeight), x1=0,                    ShowBorder='Y', BorderColor=2, TitleColor=2)
        InfoWindow    = textwindows.TextWindow  (name='InfoWindow',   title='Extra Info',rows=max_y - 1,     columns=window_width *2, y1=(HeaderHeight), x1=window_width * 3 + 1, ShowBorder='Y', BorderColor=2, TitleColor=2)
 
 
        #PacketWindow  = textwindows.TextWindow  (name='PacketWindow', title='Packets',   rows=max_y - 1,     columns=window_width,   y1=(HeaderHeight), x1=window_width * 2,     ShowBorder='Y', BorderColor=2, TitleColor=2)
        #RawWindow     = textwindows.TextWindow  (name='RawWindow',    title='Raw Data',  rows=max_y - 1,     columns=window_width,   y1=(HeaderHeight), x1=window_width * 4 + 1, ShowBorder='Y', BorderColor=2, TitleColor=2)


        # Refresh windows for initial setup
        HeaderWindow.DisplayTitle('Sentinel 1.0')
        HeaderWindow.refresh()
        
        #PacketWindow.DisplayTitle('Packet Info')
        #PacketWindow.refresh()
        
        InfoWindow.DisplayTitle('Information')
        console_width            = shutil.get_terminal_size().columns
        console_height           = shutil.get_terminal_size().lines

        InfoWindow.refresh()
        
        FormattedString = format_into_columns(DetailsWindow.columns, 'Name/Type','mac','DeviceBrand', 'SSID','Band/Channel/Signal')
        DetailsWindow.DisplayTitle(FormattedString,x=1)
        DetailsWindow.refresh()

        #RawWindow.DisplayTitle('Raw Data')
        #RawWindow.refresh()
    

        log_message(f"Height x Width {ScreenHeight}x{ScreenWidth}")    

        # Start the queue processing thread automatically
        log_message(f"Starting thread: queue_processor_thread",ShowTime=True)
        queue_processor_thread = threading.Thread(target=textwindows.ProcessQueue, daemon=True)
        queue_processor_thread.start()
        TheTime = f"{str(datetime.now())[11:19]:<8}"
        log_message(f"queue_processor_thread started",ShowTime=True)


    # Load the OUI dictionary
    oui_dict = load_oui_dict_from_json("oui_dict.json")
    #print_oui_stats(oui_dict, InfoWindow)

    # Load the friendly devices dictionary
    friendly_devices_dict = load_friendly_devices_dict("FriendlyDevices.json")
    

    # Get the Wi-Fi interface in monitor mode
    interface = get_monitor_mode_interface()
    if interface is None:
        if curses_enabled:
          InfoWindow.QueuePrint("ERROR: No interface found in monitor mode. Exiting...")
        else:
          print("ERROR: No interface found in monitor mode. Exiting...")
        time.sleep(5)
        return

    #--------------------------------------
    #-- Start threads
    #--------------------------------------

  
    #print our starting messages down the screen a bit
    if curses_enabled == False:
      console_region.current_row = 20


    # Create and start the DB processing thread
    log_message("Starting thread: process_DBQueue",ShowTime=True)
    DB_processing_thread = threading.Thread(target=process_DBQueue, name="DBProcessingThread")
    DB_processing_thread.daemon = True  # Set as daemon so it exits with the main program
    DB_processing_thread.start()

    log_message("Starting thread: process_PacketQueue",ShowTime=True)
    packet_processing_thread = threading.Thread(target=process_PacketQueue, name="PacketProcessingThread")
    packet_processing_thread.daemon = True  # Set as daemon so it exits with the main program
    packet_processing_thread.start()


    # Start the channel hopper thread
    log_message('Starting thread: channel_hopper',ShowTime=True)
    hopper_thread = threading.Thread(target=channel_hopper, args=(interface, hop_interval), name="ChannelHopperThread")
    hopper_thread.daemon = True
    hopper_thread.start()

    # Start packet sniffing thread
    log_message('Starting thread: sniff_packets',ShowTime=True)
    sniff_thread = threading.Thread(target=sniff_packets, args=(interface,), name="SniffingThread")
    sniff_thread.daemon = True  # Allows the program to exit even if the thread is running
    sniff_thread.start()

    # Start GPS thread
    log_message('Starting thread: gps_thread',ShowTime=True)
    gps_thread = threading.Thread(target=get_current_gps_coordinates, name="GPSThread")
    gps_thread.daemon = True  # Allows the program to exit even if the thread is running
    gps_thread.start()


    #print some console stuff
    if curses_enabled == False:
      log_message(f"Console size: {console_width}x{console_height}",ShowTime=True)
      console_region.print_line(text=console_region_title,line=console_region.title_row,color=Fore.LIGHTBLUE_EX)        

      #reset the starting row
      console_region.current_row = console_region.start_row





    # Create and start the periodic logging thread
    #logging_thread = threading.Thread(target=periodic_thread_logging, name="ThreadLoggerThread", daemon=True)
    #logging_thread.start()

    #----------------------------------
    #-- Main Loop
    #----------------------------------
    try:
        while True:

         

          #Check for keyboard input
          current_time = time.time()

          if current_time - last_time >= keyboard_interval:
            Key = get_keypress()
            ProcessKeypress(Key)
            last_time = current_time



          time.sleep(main_interval)
            
            # Safely read GPS coordinates
          with gps_lock:
                current_latitude = latitude
                current_longitude = longitude
                
            #LatLong = get_current_gps_coordinates()
            # Update the curses windows if needed
            #PacketWindow.window.touchwin()
            #PacketWindow.refresh()
            #InfoWindow.window.touchwin()
            #InfoWindow.refresh()
            #DetailsWindow.window.touchwin()
            #DetailsWindow.refresh()

    except KeyboardInterrupt:
        if curses_enabled:
          InfoWindow.QueuePrint("Stopping...")
        else:
          print("Stopping")
      

        gps_stop_event.set()
        gps_thread.join()  







# This block ensures that the code within it only runs when the script is executed directly,
# and not when it is imported as a module. This allows the script to be reused as a library
# while still being runnable as a standalone program.
if __name__ == "__main__":
    #Clear the screen
    print(f"\033[{1};1H", end="",flush=True)

    #Process input parameters
    print("Program arguments:", sys.argv)
    parser = argparse.ArgumentParser(description="Sentinel Program")

    # Add parameters
    parser.add_argument(
        "--Raw",
        choices=["Y", "N"],
        default="N",
        help="--Raw Y is for basic output, no  fancy text windows."
    )

    parser.add_argument(
        "--Friendly",
        choices=["Y", "N"],
        default="Y",
        help="--Friendly Y causes friendly devices to be included in the display (can be a bit noisy if sentinel is not mobile)"
    )

    parser.add_argument(
        "--Routers",
        choices=["Y", "N"],
        default="Y",
        help="--Routers Y will include routers and access points in traffic processing)"
    )


    # Parse the arguments
    args = parser.parse_args()

    # Convert the input to a boolean for easier handling
    curses_enabled = args.Raw      == "N"
    show_friendly  = args.Friendly == "Y"
    show_routers   = args.Routers  == "Y"

    if curses_enabled:
      curses.wrapper(main)
    else:
     
      #Console region
      initialize_console_region(start_row=console_start_row,stop_row=console_stop_row)
      

      # Initialize colorama for Windows compatibility
      init()
      print(Fore.RED,end="", flush=True)
      os.system('clear') #clear the terminal (optional)
      print(pyfiglet.figlet_format("    SENTINEL PASSIVE SURVEILLANCE   ",font='pagga',justify='left',width=console_width))
#      print(pyfiglet.figlet_format("                       RAW OUTPUT MODE                        ",font='pagga',justify='left',width=console_width))
      print(Fore.GREEN,end="", flush=True)


      fig = pyfiglet.Figlet(
          font="standard",      # Default font
          direction="auto",     # Default direction
          justify="auto"        # Default alignment
          
      )
      # List all available fonts
      #fonts = pyfiglet.FigletFont.getFonts()
      #print("Available Fonts:")
      #for font in fonts:
      #    print(font)
      #    print(pyfiglet.figlet_format(font, font=font))
      #    time.sleep(0.1)
      

      #Prime the packet objects
      ProcessedPacket = PacketInformation()
      main('RawMode')




