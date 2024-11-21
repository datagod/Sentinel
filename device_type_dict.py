# Expanded dictionary mapping MAC address prefixes to device types
device_type_dict = {
    # Amcrest Security Cameras
    '00:65:1E': 'Amcrest Security Camera',
    '9C:8E:CD': 'Amcrest Security Camera',
    'A0:60:32': 'Amcrest Security Camera',

    # Google Devices (e.g., Google Home, Chromecast)
    '78:DA:BB': 'Google Home/Chromecast',
    'F4:F5:DB': 'Google Home/Chromecast',
    '9C:2A:70': 'Google Nest Device',

    # Amazon Devices (e.g., Echo, Firestick)
    '44:E9:DD': 'Amazon Echo Device',
    'D0:68:EB': 'Amazon Echo Device',
    'BC:54:F9': 'Amazon Firestick',

    # Ring Security Cameras
    'CC:2D:B7': 'Ring Security Camera',
    '18:45:D8': 'Ring Doorbell',

    # Netgear Routers
    'A4:2B:8C': 'Netgear Router',
    'B0:48:7A': 'Netgear Router',
    '1C:1B:0D': 'Netgear Router',

    # Cisco Access Points
    '00:2A:6A': 'Cisco Access Point',
    'F8:C0:01': 'Cisco Access Point',
    '00:C0:B7': 'Cisco Router/Switch',

    # TP-Link Devices
    'AC:84:C6': 'TP-Link Router',
    'F4:EC:38': 'TP-Link Router',
    'C4:E9:84': 'TP-Link IoT Device',

    # Philips Hue (Smart Bulbs)
    '00:17:88': 'Philips Hue Bulb',
    'A0:C9:A0': 'Philips Hue Hub',

    # Wyze Devices (Cameras, Smart Plugs)
    '2C:AA:8E': 'Wyze Camera',
    '7C:49:EB': 'Wyze Smart Plug',

    # D-Link Devices
    'B0:C5:54': 'D-Link Router',
    '14:CF:92': 'D-Link Camera',

    # Huawei Devices (Phones, Routers)
    '38:F3:AB': 'Huawei Mobile Phone',
    '8C:11:CB': 'Huawei Router',

    # Apple Devices (iPhones, iPads, Macs)
    'BC:92:B5': 'Apple iPhone',
    '3C:07:54': 'Apple iPad',
    '7C:B7:7B': 'Apple MacBook',

    # Samsung Devices (Phones, Tablets)
    '88:E3:AB': 'Samsung Mobile Phone',
    '5C:49:7D': 'Samsung Tablet',
    '14:A3:64': 'Samsung Smart TV',

    # OnePlus Devices
    'BC:14:85': 'OnePlus Mobile Phone',
    'A4:D8:CA': 'OnePlus Mobile Phone',

    # Lenovo Devices (Laptops)
    'FC:F1:5B': 'Lenovo Laptop',
    '08:EB:ED': 'Lenovo Laptop',

    # Dell Devices (Laptops, Desktops)
    '00:25:68': 'Dell Laptop',
    'A4:BA:DB': 'Dell Desktop',

    # HP Devices (Laptops, Printers)
    'EC:8A:CF': 'HP Laptop',
    'BC:5F:F4': 'HP Printer',

    # Xiaomi Devices (Phones, IoT)
    '7C:49:EB': 'Xiaomi Mobile Phone',
    '64:B3:10': 'Xiaomi Smart Device',

    # Sony Devices (Smart TVs)
    'AC:9B:0A': 'Sony Smart TV',
    '54:EE:75': 'Sony PlayStation',

    # Panasonic Cameras
    '00:20:D6': 'Panasonic Security Camera',
    '00:E0:36': 'Panasonic IP Camera',
    
    # Hikvision Cameras
    'F4:E9:9A': 'Hikvision Security Camera',
    '4C:E6:76': 'Hikvision IP Camera',

    # Ubiquiti Devices (Access Points, Routers)
    '24:A4:3C': 'Ubiquiti Access Point',
    '78:30:C3': 'Ubiquiti Router',
    
    # Ring (Smart Cameras and Doorbells)
    '18:22:7E': 'Ring Camera/Doorbell',
    
    # Arlo Cameras
    '00:C0:CA': 'Arlo Security Camera',
    'F4:F5:E8': 'Arlo Camera Hub',

    # Bosch Security Cameras
    '00:1A:8C': 'Bosch Security Camera',
    '00:1B:EB': 'Bosch IP Camera',

    # Axis Communications Cameras
    '00:40:8C': 'Axis Communications Camera',
    'AC:CC:8E': 'Axis IP Camera',

    # Logitech Devices
    '00:07:7C': 'Logitech Device',
    '00:1F:20': 'Logitech Webcam',

    # Microsoft Devices
    '00:1D:D8': 'Microsoft Device',
    '00:1E:65': 'Microsoft Surface',

    # ASUS Devices
    '00:1A:92': 'ASUS Device',
    '00:1B:FC': 'ASUS Router',

    # LG Electronics Devices
    '00:1C:62': 'LG Electronics Device',
    '00:1D:7E': 'LG Smart TV',

    # Motorola Devices
    '00:0C:E5': 'Motorola Device',
    '00:12:25': 'Motorola Mobile Phone',

    # Nokia Devices
    '00:15:A0': 'Nokia Device',
    '00:16:4E': 'Nokia Mobile Phone',

    # ZTE Devices
    '00:19:CB': 'ZTE Device',
    '00:1A:2A': 'ZTE Mobile Phone',

    # Oppo Devices
    '00:1B:63': 'Oppo Mobile Phone',
    '00:1C:26': 'Oppo Device',

    # Vivo Devices
    '00:1D:0F': 'Vivo Mobile Phone',
    '00:1E:10': 'Vivo Device',

    # Realme Devices
    '00:1F:3B': 'Realme Mobile Phone',
    '00:20:91': 'Realme Device',

    # TCL Devices
    '00:21:6A': 'TCL Device',
    '00:22:3F': 'TCL Smart TV',

    # Hisense Devices
    '18:30:0C': 'Hisense Device',
    '38:F5:54': 'Hisense Device',
    '5C:34:00': 'Hisense Device',
    'A8:82:00': 'Hisense Device',
    '08:D0:B7': 'Hisense Device',
    '1C:7B:23': 'Hisense Device',
    '24:E2:71': 'Hisense Device',
    '2C:FE:E2': 'Hisense Device',
    '34:0A:FF': 'Hisense Device',
    '40:CD:7A': 'Hisense Device',
    '58:7E:61': 'Hisense Device',
    '8C:9F:3B': 'Hisense Device',
    '90:CF:7D': 'Hisense Device',
    'A8:A6:48': 'Hisense Device',
    'BC:60:10': 'Hisense Device',
    'C8:16:BD': 'Hisense Device',
    'EC:E6:60': 'Hisense Device',

    # Bosch Security Cameras
    '00:1A:8C': 'Bosch Security Camera',
    '00:1B:EB': 'Bosch IP Camera',

    # Axis Communications Cameras
    '00:40:8C': 'Axis Communications Camera',
    'AC:CC:8E': 'Axis IP Camera',

    # Logitech Devices
    '00:07:7C': 'Logitech Device',
    '00:1F:20': 'Logitech Webcam',

    # Microsoft Devices
    '00:1D:D8': 'Microsoft Device',
    '00:1E:65': 'Microsoft Surface',

    # ASUS Devices
    '00:1A:92': 'ASUS Device',
    '00:1B:FC': 'ASUS Router',

    # LG Electronics Devices
    '00:1C:62': 'LG Electronics Device',
    '00:1D:7E': 'LG Smart TV',

    # Motorola Devices
    '00:0C:E5': 'Motorola Device',
    '00:12:25': 'Motorola Mobile Phone',

    # Nokia Devices
    '00:15:A0': 'Nokia Device',
    '00:16:4E': 'Nokia Mobile Phone',

    # ZTE Devices
    '00:19:CB': 'ZTE Device',
    '00:1A:2A': 'ZTE Mobile Phone',

    # Oppo Devices
    '00:1B:63': 'Oppo Mobile Phone',
    '00:1C:26': 'Oppo Device',

    # Vivo Devices
    '00:1D:0F': 'Vivo Mobile Phone',
    '00:1E:10': 'Vivo Device',

    # Realme Devices
    '00:1F:3B': 'Realme Mobile Phone',
    '00:20:91': 'Realme Device',

    # TCL Devices
    '00:21:6A': 'TCL Device',
    '00:22:3F': 'TCL Smart TV',
}

 
