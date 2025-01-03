import sqlite3
import os

db_path = "packet.db"

"""
Create a SQLite database with tables to store packet data, raw packets, tags, and packet-tag relationships.

:param db_path: Path to the SQLite database file.
"""

try:
    # Check if the database already exists
    if os.path.exists(db_path):
        print(f"Database '{db_path}' already exists. Skipping creation.")

    # Connect to the SQLite database (creates the file if it doesn't exist)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Define SQL statements to create the tables
    table_queries = {
        "Packet": '''
            CREATE TABLE IF NOT EXISTS Packet (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                CaptureDate DATETIME DEFAULT CURRENT_TIMESTAMP,
                FriendlyName TEXT,
                FriendlyType TEXT,
                PacketType TEXT,
                DeviceType TEXT,
                SourceMAC TEXT,
                SourceVendor TEXT,
                DestMAC TEXT,
                DestVendor TEXT,
                SSID TEXT,
                Band TEXT,
                Channel TEXT,
                Latitude REAL,
                Longitude REAL,
                Signal INTEGER
            );
        ''',
        "RawPacket": '''
            CREATE TABLE IF NOT EXISTS RawPacket (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                packet TEXT
            );
        ''',
        "Tag": '''
            CREATE TABLE IF NOT EXISTS Tag (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT
            );
        ''',
        "PacketTag": '''
            CREATE TABLE IF NOT EXISTS PacketTag (
                PacketID INTEGER,
                TagID INTEGER
            );
        ''',
        "vPacket": '''
            CREATE view IF NOT EXISTS vPacket as
                select p.*, t.*
                  from Packet          p
                  left join PacketTag pt on pt.PacketID = p.ID
                  join Tag             t on t.ID     = pt.TagID
            ;
        ''',
        "vPacket": '''

CREATE VIEW IF NOT EXISTS vPacketTags AS
SELECT 
    p.*,
    GROUP_CONCAT(t.tag, ', ') AS Tag
FROM 
    Packet p
LEFT JOIN 
    PacketTag pt ON pt.PacketID = p.id
LEFT JOIN 
    Tag t ON t.id = pt.TagID
GROUP BY 
    p.id;
''',



        "indexes": '''
      
         create index i_Packet_capturedate on Packet(CaptureDate);
         create index i_Packet_SourceMAC on Packet(SourceMAC);
         create unique index ui_PacketTag on PacketTag(PacketID, TagID);
         create index i_Tag_tag on Tag(tag);

            );
        '''

    }

    # Execute each table creation query
    for table_name, query in table_queries.items():
        print(f"Command found: {table_name}")
        #if table_name in ('vPacket','PacketTag','Tag'):
            print("Executing command...")
            cursor.execute(query)
            print("done")
            print(f"Object '{table_name}' created successfully in the database.")

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

except sqlite3.Error as e:
    print(f"SQLite error: {e}")

print("Script finished.")
