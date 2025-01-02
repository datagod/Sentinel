from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

def get_db_connection():
    db_path = "/home/pi/sentinel/packet.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn




# Route for the homepage to display Packet records
@app.route('/')
def home():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    conn   = get_db_connection()
    params = []
    query  = 'SELECT * FROM vPacket '

    query += "where 1=1"

    if start_date and end_date:
        query += ' and CaptureDate BETWEEN ? AND ?'
        params.extend([start_date, end_date])

    query += " and ssid not like '%empire%'"
    query = query + ' order by CaptureDate desc LIMIT 500'

    packets = conn.execute(query, params).fetchall()
    conn.close()
    return render_template('index.html', packets=packets, start_date=start_date, end_date=end_date)

# Route to handle adding a tag
@app.route('/add_tag', methods=['POST'])
def add_tag():
    packet_id = request.form['packet_id']
    tag = request.form['tag'].lower()

    conn = get_db_connection()
    # Check if the tag already exists
    tag_row = conn.execute('SELECT id FROM Tag WHERE tag = ?', (tag,)).fetchone()

    if tag_row:
        tag_id = tag_row['id']
    else:
        # Insert the new tag into the Tag table
        conn.execute('INSERT INTO Tag (tag) VALUES (?)', (tag,))
        conn.commit()
        tag_id = conn.execute('SELECT id FROM Tag WHERE tag = ?', (tag,)).fetchone()['id']

    # Insert the PacketID and TagID into PacketTag
    conn.execute('INSERT INTO PacketTag (PacketID, TagID) VALUES (?, ?)', (packet_id, tag_id))
    conn.commit()
    conn.close()

    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True) 
