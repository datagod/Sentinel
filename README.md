# Sentinel Passive Surveillance System

![image](https://github.com/user-attachments/assets/6a547625-ca1e-4527-8d2a-9405fc0ca5a3)


## Overview
The **Sentinel Passive Surveillance System** is a robust passive network surveillance tool designed for capturing and analyzing Wi-Fi packets. It identifies devices, extracts metadata such as MAC addresses, SSIDs, vendors, and protocols, and provides detailed analysis through a text-based user interface or raw console output.

---

## Features
- **Packet Sniffing**: Capture 802.11 packets, ARP packets, and more using the Scapy library.
- **Device Identification**: Extract and analyze MAC addresses, vendors, SSIDs, and determine device types using OUI lookups.
- **Channel Hopping**: Automatically switches Wi-Fi channels to capture packets across 2.4 GHz and 5 GHz bands.
- **Curses-Based UI**: A curses-based multi-window text interface displays detailed information about packets and devices.
- **Raw Mode**: Supports a simpler text-only interface for minimal environments.
- **Packet Logging**: Store captured packet details in a SQLite database for post-capture analysis.
- **GPS Integration**: Capture geographical coordinates (latitude and longitude) alongside network data.
- **Reports**:
  - Top devices by frequency
  - Top mobile devices
  - Recent intruders
- **Threading**: Efficient multithreading to handle packet processing, database operations, and channel hopping concurrently.
- **Profiling**: Built-in performance profiling to identify slowest functions.

---

## Prerequisites

### Hardware
- A Wi-Fi adapter capable of monitor mode
    - Alfa Network AWUS036ACM on a Raspberry Pi 4
    - Panda PAU0B AC600 works on Raspberry Pi 3B+
- GPS device for location-based packet data (optional).
- Raspberry Pi or other Linux-based systems.

### Software
- Python 3.8+
- Operating System: Linux (preferred) with monitor mode capabilities enabled.
- Libraries:
  - [Scapy](https://scapy.net/)
  - [Curses](https://docs.python.org/3/library/curses.html)
  - [Cachetools](https://github.com/tkem/cachetools)
  - [Colorama](https://pypi.org/project/colorama/)
  - [Pyfiglet](https://pypi.org/project/pyfiglet/)
  - [GPS](https://pypi.org/project/gps/)
  - [Netaddr](https://pypi.org/project/netaddr/)
  - [SQLite3](https://www.sqlite.org/index.html)
- Tools:
  - `iw` for managing Wi-Fi interfaces.
  - `sudo` for elevated privileges.

---

## Installation

1. Clone the Repository:
   ```bash
   git clone https://github.com/<username>/sentinel.git
   cd sentinel
   ```

2. Install Dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Enable Monitor Mode:
   ```bash
   sudo iw dev wlan0 interface add mon0 type monitor
   sudo ifconfig mon0 up
   ```
   Replace `wlan0` with your Wi-Fi interface name.

4. Load Required JSON Files:
   - `oui_dict.json`: OUI vendor information.
   - `FriendlyDevices.json`: List of trusted devices.

5. Set Permissions:
   ```bash
   chmod +x sentinel.py
   ```

---

## Setting Up the Database

To store captured packet data and related information, the Sentinel system uses an SQLite database. Follow the steps below to create the necessary database and tables.

### Prerequisites

- Ensure Python 3 is installed on your system.
- The `sqlite3` library is included by default in Python, so no additional installation is necessary.

### Steps to Create the Database

1. **Run the Script**
   Execute the script in a terminal or command prompt using Python 3:

   ```bash
   python3 create_database.py
   ```

3. **Verify the Database**
   After running the script:
   - A file named `packet.db` will be created in the current directory.
   - Inside the database:
     - `Packet` table stores processed packet details, including metadata like MAC addresses, SSIDs, and signal strength.
     - `RawPacket` table stores raw packet data for advanced analysis.

4. **Using the Database**
   The `sentinel.py` script will automatically detect and use the `packet.db` database during operation.

---



---

## Usage
### Launching Sentinel in RAW Mode
For simplified output without the text windows, Sentinel can be launched in RAW Mode. A Bash script is included to handle the setup and execution.

#### Included Script

`raw.sh`, is provided to streamline launching Sentinel in RAW Mode:

#### What the Script Does
1. **Clear the Console:** Clears the terminal for a clean output.
2. **Set Up Colors:** Defines color codes for terminal output for better readability.
3. **Navigate to Sentinel Directory:** Switches to the directory where Sentinel is located.
4. **Prevent Duplicate Instances:** Checks if Sentinel is already running and exits if so.
5. **Configure Wi-Fi Interface:** Switches `wlan1` to monitor mode for packet capture.
6. **Launch Sentinel:** Starts Sentinel in RAW Mode with the following options:
   - `--Raw Y`: Enables RAW Mode.
   - `--Friendly Y`: Includes friendly devices in the display.
   - `--Routers Y`: Includes routers and access points in the traffic processing.
7. **Clean Up:** Ensures the terminal is restored to a sane state after execution.

#### Using the Script

1. **Make the Script Executable**
   Ensure the script has execute permissions:
   ```bash
   chmod +x launch_raw_mode.sh
   ```

2. **Run the Script**
   Execute the script to launch Sentinel in RAW Mode:
   ```bash
   ./launch_raw_mode.sh
   ```

3. **Output**
   - The terminal will display a confirmation if Sentinel is already running.
   - The script configures the Wi-Fi interface and launches Sentinel with the specified parameters.

4. **After Use**
   The terminal is reset to a sane state to ensure it functions correctly after the script completes.

---


### Launching the Application Directly
Run the Sentinel program:
```bash
sudo python3 sentinel.py
```

### Command-Line Arguments
- `--Raw [Y/N]`: Toggle between raw output mode and curses-based UI.
- `--Friendly [Y/N]`: Include/exclude friendly devices in the display.
- `--Routers [Y/N]`: Include/exclude routers and access points in the display.

Example:
```bash
sudo python3 sentinel.py --Raw Y --Friendly N --Routers Y
```

### Keyboard Shortcuts (Interactive Mode)
| Key  | Action                          |
|------|---------------------------------|
| `q`  | Quit the program               |
| `p`  | Pause for 5 seconds            |
| `f`  | Toggle friendly devices display|
| `r`  | Toggle routers display         |
| `t`  | Toggle curses/raw mode         |
| `R`  | Restart the program            |
| `1`  | Generate top devices report    |
| `2`  | Generate top mobile report     |
| `3`  | Generate recent intruders report|
| `c`  | Clear the console              |

---

## Architecture

### Core Modules
1. **Packet Sniffing**:
   - Uses Scapy to sniff packets in monitor mode.
   - Supports multiple protocols (e.g., ARP, DHCP, Dot11).

2. **Channel Hopping**:
   - Automatically switches channels to ensure comprehensive packet capture.
   - Separate thread for non-blocking execution.

3. **Database Integration**:
   - Stores packet metadata in SQLite for future analysis.
   - SQL queries for generating detailed reports.

4. **User Interface**:
   - Curses-based windows for displaying packet details, logs, and headers.
   - Raw text mode for headless environments.

5. **Device Identification**:
   - Identifies devices using OUI and MAC vendor lookups.
   - Determines device types (e.g., Mobile, Router, IoT).

6. **Reports**:
   - Generates reports on device activity using SQL queries.

---

## Output Examples

### Reports Example
**Top 25 Devices Today**
![image](https://github.com/user-attachments/assets/2b50480d-9c32-4b18-b212-53beac21c2be)



### Curses UI Example
```plaintext
+-----------------------------------------------------+
|                   Sentinel 1.0                     |
|-----------------------------------------------------|
| Packets Processed:  1500  | Show Friendly: Yes     |
| Band: 2.4 GHz        | Channel: 6                 |
|-----------------------------------------------------|
| Details:                                           |
| Name/Type           | MAC Address | Vendor | SSID |
+-----------------------------------------------------+
```

### Raw Output Example
```plaintext
Time     Friendly  PacketType   DeviceType  SourceMac       SourceVendor      SSID
12:00:01 Yes       Beacon       Router      00:11:22:33:44 TP-Link           HomeWiFi
```

---

## Troubleshooting

### Common Issues
- **No packets captured**:
  - Ensure the Wi-Fi adapter is in monitor mode.
  - Verify the interface name in the script.
- **GPS not working**:
  - Check if GPSD is running.
  - Ensure GPS hardware is connected properly.
- **Permission denied**:
  - Run the program with `sudo`.

### Debugging
- Enable verbose logging by modifying the `log_message()` function.
- Use `print` statements or the curses `QueuePrint` method for additional debugging.

---

## Future Enhancements
- Integration with machine learning models for device fingerprinting.
- Real-time map visualization using Folium.
- Enhanced reporting with graphs and analytics.
- Better handling of MAC address randomization.
- Integration with cloud-based monitoring systems.

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contributors
- **Bill (Datagod)** - Creator and primary developer.
- ** ChatGPT (Chris) - A.I. coding partner

---

## Acknowledgments
- Special thanks to the developers of Scapy, Cachetools, and Pyfiglet for their excellent tools.
- Inspiration from various network monitoring and security tools.

---

## Contact
For questions, issues, or contributions, please contact:
- **GitHub**: [Datagod](https://github.com/datagod)

