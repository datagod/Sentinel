import sqlite3
import os
db_path = "packet.db"
"""
Create a SQLite database with a table to store packet data.

:param db_path: Path to the SQLite database file.
"""
try:
    # Check if the database already exists
    if os.path.exists(db_path):
        print(f"Database '{db_path}' already exists. Skipping creation.")

    # Connect to the SQLite database (creates the file if it doesn't exist)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Define SQL statement to create a table for packet data
    create_table_query = '''
    CREATE TABLE IF NOT EXISTS Packet (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        CaptureDate DATETIME DEFAULT CURRENT_TIMESTAMP,
        FriendlyName TEXT,
        FriendlyType TEXT,
        PacketType   TEXT,
        DeviceType   TEXT,
        SourceMAC    TEXT,
        SourceVendor TEXT,
        DestMAC      TEXT,
        DestVendor   TEXT,
        SSID         TEXT,
        Band         TEXT,
        Channel      TEXT

    );
    '''
    # Execute the SQL statement to create the table
    cursor.execute(create_table_query)
    print("Table 'Packet' created successfully in the database.")
    # Commit the changes and close the connection
    conn.commit()
    

    create_table_query = '''
    CREATE TABLE IF NOT EXISTS RawPacket (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,            
        packet TEXT
    );

    '''
    # Connect to the SQLite database (creates the file if it doesn't exist)
    # conn = sqlite3.connect(db_path)
    # Execute the SQL statement to create the table
    cursor.execute(create_table_query)
    print("Table 'RawPacket' created successfully in the database.")

    # Commit the changes and close the connection
    conn.commit()


    sql = '''
    select * from Packet;
    '''
    # Connect to the SQLite database (creates the file if it doesn't exist)
    # conn = sqlite3.connect(db_path)
    # Execute the SQL statement to create the table
    cursor.execute(sql)
    results = cursor.fetchall()
    # Print the packet data for verification
    for result in results:
            print(result)

    
    # Commit the changes and close the connection
    conn.commit()









    conn.close()

except sqlite3.Error as e:
    print(f"SQLite error: {e}")
# Ensure the connection is closed
print("Script finished...but did it work?")

