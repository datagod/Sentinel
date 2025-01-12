
from flask import Flask, render_template, request, redirect, url_for, render_template_string
import sqlite3
import folium
from colorama import Fore, Back, Style, init
from datetime import datetime



app = Flask(__name__)

def get_db_connection():
    db_path = "/home/pi/sentinel/packet.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def home():
    print(Fore.GREEN,"-------------------------------------------------------")
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = request.args.get('page', 1, type=int)  # Default to page 1
    records_per_page = 500
    offset = (page - 1) * records_per_page

    if not end_date:
        end_date = datetime.now()

    conn = get_db_connection()
    params = []
    query = 'SELECT * FROM vPacketTags WHERE 1=1'

    if start_date and end_date:
        start_datetime = f"{start_date} 00:00:00"
        end_datetime = f"{end_date} 23:59:59"
        query += " and FriendlyName is null"
        query += ' AND CaptureDate BETWEEN ? AND ?'
        params.extend([start_datetime, end_datetime])

    query += ' ORDER BY CaptureDate DESC LIMIT ? OFFSET ?'
    params.extend([records_per_page, offset])

    try:
        print(f"Execute: {query}",records_per_page, offset)
        packets = conn.execute(query, params).fetchall()
        print(f"Rows affected: {len(packets)}")
    except Exception as e:
        error_message = f"SQLite error: {e.args[0]}"
        print(Fore.RED,error_message)
        return render_template('error.html', error_message=error_message), 500
    finally:
        conn.close()

    print("-------------------------------------------------------")
    return render_template(
        'index.html', 
        packets=packets, 
        start_date=start_date, 
        end_date=end_date, 
        page=page  # Pass the page variable here
    )








@app.route('/add_tag', methods=['POST'])
def add_tag():
    print(Fore.YELLOW,"-------------------------------------------------------")
    SourceMAC = request.form['SourceMAC']
    tag = request.form['tag'].strip().lower()

    conn = get_db_connection()

    try:
        # Start a transaction
        conn.execute('BEGIN')

        # Check if the tag already exists
        print(f"Checking to see if tag ({tag}) already exists")
        tag_row = conn.execute('SELECT id FROM Tag WHERE tag = ?', (tag,)).fetchone()

        if tag_row:
            tag_id = tag_row['id']

        else:
            # Insert the new tag and retrieve its ID
            print ("Tag not found.  Creating new tag.")
            conn.execute('INSERT INTO Tag (tag) VALUES (?)', (tag,))
            tag_id = conn.execute('SELECT id FROM Tag WHERE tag = ?', (tag,)).fetchone()['id']

        print (f"Tag ID: {tag_id}")


        # Insert into PacketTag only if the relationship does not exist
        sql = """
        INSERT INTO PacketTag (PacketID, TagID)
        SELECT ID, ?
        FROM Packet
        WHERE SourceMAC = ?
        AND NOT EXISTS (
            SELECT 1
            FROM PacketTag
            WHERE PacketTag.PacketID = Packet.ID AND PacketTag.TagID = ?
        )
        """
        print(f"Executing: {sql}")
        conn.execute(sql, (tag_id, SourceMAC, tag_id))
        print(f"Rows affected: {conn.total_changes}")

        # Commit the transaction
        conn.commit()

    except Exception as e:
        # Rollback on error and log details
        conn.rollback()
        error_message = "An error occurred while processing your request."
        print(Fore.RED,f"SQLite error: {e.args[0]}")  # Replace with logging in production
        return render_template('error.html', error_message=error_message), 500

    finally:
        conn.close()

    print("-------------------------------------------------------")
    return redirect(url_for('home'))








@app.route('/map')
def map_view():
    conn = get_db_connection()
    query = '''
    SELECT Latitude, Longitude, SourceMAC, CaptureDate 
    FROM Packet
    WHERE Latitude IS NOT NULL AND Longitude IS NOT NULL
    ORDER BY CaptureDate DESC
    LIMIT 2000
    '''
    try:
        packets = conn.execute(query).fetchall()
    except Exception as e:
        error_message = f"SQLite error: {e.args[0]}"
        print(error_message)
        return render_template('error.html', error_message=error_message), 500
    finally:
        conn.close()

    # Create a Folium map centered on Ottawa (default location)
    folium_map = folium.Map(location=[45.4215, -75.6972], zoom_start=12)

    # Add markers for each packet
    for packet in packets:
        folium.Marker(
            location=[packet['Latitude'], packet['Longitude']],
            popup=f"""
                <b>Source MAC:</b> {packet['SourceMAC']}<br>
                <b>Capture Date:</b> {packet['CaptureDate']}
            """,
            icon=folium.Icon(color='blue', icon='info-sign')
        ).add_to(folium_map)

    # Save the map as an HTML file
    map_file = '/tmp/map.html'
    folium_map.save(map_file)

    # Serve the map file
    return render_template_string(open(map_file).read())



@app.route('/source_mac/<source_mac>')
def source_mac_report(source_mac):
    conn = get_db_connection()
    query = '''
    SELECT * FROM vPacketTags
    WHERE SourceMAC = ?
    ORDER BY CaptureDate DESC
    LIMIT 500
    '''
    try:
        packets = conn.execute(query, (source_mac,)).fetchall()
    except Exception as e:
        error_message = f"SQLite error: {e.args[0]}"
        print(error_message)
        return render_template('error.html', error_message=error_message), 500
    finally:
        conn.close()

    return render_template('source_mac_report.html', packets=packets, source_mac=source_mac)




if __name__ == '__main__':
    app.run(host='192.168.0.197',port=5000, debug=True) 
