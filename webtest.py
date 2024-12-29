import sqlite3
import folium

# Connect to SQLite database
db_path = "packet.db"  # Replace with the path to your database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Query the most recent 100 packets
query = """
SELECT Latitude, Longitude, SSID
FROM Packet
ORDER BY CaptureDate DESC
LIMIT 100;
"""
cursor.execute(query)
rows = cursor.fetchall()

# Create the map
center_lat, center_lon = 45.1703, -75.9312  # Replace with default center coordinates
map_ = folium.Map(location=[center_lat, center_lon], zoom_start=12)

# Add markers for each packet
for row in rows:
    Latitude, Longitude, SSID = row
    print(f"lat:{Latitude} lon:{Longitude} SSID:{SSID}")

    folium.Marker(
        location=[Longitude,Latitude],
        popup=f"ID: {SSID}<br>",
    ).add_to(map_)

# Save the map as an HTML file
map_file = "/var/www/mywebsite/packets_map.html"  # Replace with the Nginx web directory path
map_.save(map_file)
print(f"Map saved at {map_file}. Serve it via Nginx.")

# Close database connection
conn.close()
