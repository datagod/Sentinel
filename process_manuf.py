import os

def load_manuf_file(filename):
    """
    Load the manuf file from Wireshark and create a dictionary for OUI lookup.
    
    :param filename: Path to the manuf file.
    :return: Dictionary mapping MAC prefixes to a tuple of (short description, long description).
    """
    oui_dict = {}

    if not os.path.exists(filename):
        print(f"Error: manuf file '{filename}' not found.")
        return oui_dict

    with open(filename, 'r') as file:
        for line in file:
            # Strip whitespace from the beginning and end of the line
            line = line.strip()
            
            # Ignore empty lines and comments (lines starting with #)
            if not line or line.startswith("#"):
                continue
            
            # Split the line into parts based on whitespace
            parts = line.split(maxsplit=2)  # Split into at most 3 parts (OUI, short desc, long desc)
            if len(parts) < 2:
                continue  # Skip lines without sufficient data
            
            # The first part is the prefix, the second part is the short description, the third (optional) is the long description
            prefix = parts[0].replace('-', ':').upper()  # Normalize format (e.g., replace '-' with ':')
            short_desc = parts[1]
            long_desc = parts[2] if len(parts) > 2 else short_desc  # If no long description, use short description

            # Add to dictionary
            oui_dict[prefix] = (short_desc, long_desc)

    return oui_dict

# Example usage
if __name__ == "__main__":
    manuf_file_path = "manuf"  # Replace with the path to your Wireshark manuf file
    oui_dict = load_manuf_file(manuf_file_path)
    
    # Test lookup
    test_macs = [
        "00:00:0C:AA:BB:CC",  # Cisco
        "28:D2:44:11:22:33",  # Some other MAC
        "00:00:10:44:55:66"   # Hewlett Packard
    ]

    for mac in test_macs:
        mac_prefix = mac[:8].upper()  # Extract prefix (first 8 characters)
        vendor_info = oui_dict.get(mac_prefix, ("Unknown", "Unknown or Not Registered"))
        print(f"MAC: {mac}, Vendor Short: {vendor_info[0]}, Vendor Long: {vendor_info[1]}")
