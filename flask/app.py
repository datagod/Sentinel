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
    sql = ''

    print("-------------------------------------------------------")
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    conn   = get_db_connection()
    params = []
    query  = 'SELECT * FROM vPacketTags '

    query += "where 1=1"

    if start_date and end_date:
        query += ' and CaptureDate BETWEEN ? AND ?'
        params.extend([start_date, end_date])

    #query += " and ssid not like '%empire%'"
    query += " and ssid <> 'UNKNOWN'"
    #query += " and FriendlyName like '%amcrest%'"
    #query += " and ssid <> ''"
    #query += " and tag is null"
    #query += " and tag not in ('home','phone','camera')"
    query += " and CaptureDate >= '2024-12-31'"
    query = query + ' order by SourceMAC LIMIT 1000'

    try:
      print (f"Execute: {sql}")
      packets = conn.execute(query, params).fetchall()
      print(f"Rows affected: {conn.total_changes}")
      conn.close()

    except Exception as e:
        # Log the error and optionally display it
        error_message = f"SQLite error: {e.args[0]}"
        print(error_message)  # Log to console (or use a logging library)
        return render_template('error.html', error_message=error_message), 500
    finally:
        conn.close()
    print("-------------------------------------------------------")



    return render_template('index.html', packets=packets, start_date=start_date, end_date=end_date)

# Route to handle adding a tag
@app.route('/add_tag', methods=['POST'])
def add_tag():
    print("-------------------------------------------------------")
    #packet_id  = request.form['packet_id']
    SourceMAC  = request.form['SourceMAC']
    tag = request.form['tag'].lower()

    sql = ''

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

    try:
        sql = f"INSERT INTO PacketTag (PacketID, TagID) select ID, {tag_id} from Packet where SourceMAC = '{SourceMAC}'"
        # Insert the PacketID and TagID into PacketTag
        print (f"Execute: {sql}")
        conn.execute(sql)
        print(f"Rows affected: {conn.total_changes}")
        conn.commit()
    

    except Exception as e:
        # Log the error and optionally display it
        error_message = f"SQLite error: {e.args[0]}"
        print(error_message)  # Log to console (or use a logging library)
        conn.rollback()
        return render_template('error.html', error_message=error_message), 500
    finally:
        conn.close()
    print("-------------------------------------------------------")

    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True) 
