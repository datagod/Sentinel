# Sentinel Passive Surveillance

## Overview
The Sentinel program is designed for monitoring and securing network environments by identifying devices within a secure zone and ensuring full visibility of Wi-Fi activity. It utilizes Wi-Fi channel hopping and packet sniffing to monitor devices across all available in 2.4 and 5 GHz channels, including both DFS and non-DFS. Sentinel is ideal for network diagnostics, security analysis, and detecting rogue devices in a monitored area.

The tool operates by hopping between Wi-Fi channels while in **promiscuous mode**, listening for management, data, and beacon frames to provide a comprehensive view of the wireless environment.

## Features
- **Channel Hopping**: Continuously hops across specified Wi-Fi channels, both DFS and non-DFS, for thorough monitoring.
- **Configurable Dwell Time**: Adjustable dwell time on each channel to strike a balance between rapid scanning and comprehensive data collection.
- **Rogue Device Detection**: Helps detect unauthorized devices operating in the secure zone.
- **DFS Channel Inclusion**: Ensures complete visibility, even of devices using less congested DFS channels.

## Requirements
- **Linux-based System** (e.g., Ubuntu, Kali Linux)
- **Wi-Fi Adapter** that supports promiscuous mode (e.g., Alfa Network, Atheros chipset)
- Python 3.x (for running the example script)

### Dependencies
- **iw**: For managing Wi-Fi interface settings.
- **aircrack-ng suite** (optional): Tools like `airodump-ng` for advanced sniffing features.

## Setup
1. Ensure your Wi-Fi adapter supports **promiscuous mode**.
2. Install necessary tools:
   ```sh
   sudo apt update
   sudo apt install iw aircrack-ng
   ```
3. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/sentinel-program
   cd sentinel-program
   ```
4. Make the script executable (if applicable):
   ```sh
   chmod +x sentinel.py
   ```

## Usage
1. Set your Wi-Fi adapter to monitor mode:
   ```sh
   sudo ip link set wlan0 down
   sudo iw dev wlan0 set type monitor
   sudo ip link set wlan0 up
   ```

2. Run the Sentinel script:
   ```sh
   python3 sentinel.py
   ```
   The script will continuously hop across channels with a default dwell time of **500 ms** per channel. Modify the `channels` and `dwell_time` parameters in the script as needed.

### Example Python Sniffing Script
```python
import os
import time

# List of Wi-Fi channels, including DFS channels for comprehensive scanning
channels = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
dwell_time = 0.5  # Time to dwell on each channel (in seconds)

while True:
    for channel in channels:
        os.system(f"iw dev wlan0 set channel {channel}")
        time.sleep(dwell_time)
```

## Recommendations
- **Non-DFS Focus**: If speed is a priority and you want a quick scan of common channels, focus only on **non-DFS channels** (e.g., 36, 40, 44, 48, 149, 153, 157, 161, 165).
- **DFS Inclusion**: If full coverage is needed, make sure to include DFS channels but adjust dwell times to capture meaningful data.

## Contributing
Feel free to submit **pull requests** or **issues** to improve functionality, add features, or fix bugs.

## License
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Disclaimer
This tool is intended for **educational and security research purposes only**. Ensure that you have proper authorization to monitor Wi-Fi traffic and adhere to local laws and regulations.

## Contact
For questions, feel free to reach out or submit an issue. Contributions are welcome!

- GitHub: [yourusername](https://github.com/yourusername)
- Email: your-email@example.com

