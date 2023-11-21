import sqlite3

def create_database():
    connection = sqlite3.connect('nmap_results.db')
    cursor = connection.cursor()

    # Create tables if they don't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY,
            hostname TEXT,
            ip_address TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS open_ports (
            id INTEGER PRIMARY KEY,
            portid INTEGER,
            protocol TEXT,
            state TEXT,
            service_name TEXT,
            service_version TEXT,
            host_id INTEGER,
            FOREIGN KEY (host_id) REFERENCES hosts (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traceroute (
            id INTEGER PRIMARY KEY,
            ttl INTEGER,
            rtt TEXT,
            address TEXT,
            host_id INTEGER,
            FOREIGN KEY (host_id) REFERENCES hosts (id)
        )
    ''')

    connection.commit()
    connection.close()

# Function to insert parsed data into the SQLite database
def insert_into_database(parsed_data):
    connection = sqlite3.connect('nmap_results.db')
    cursor = connection.cursor()

    # Insert host information
    cursor.execute('''
        INSERT INTO hosts (hostname, ip_address)
        VALUES (?, ?)
    ''', (parsed_data['host_info']['hostname'], parsed_data['host_info']['ip_address']))

    host_id = cursor.lastrowid  # Get the ID of the last inserted host

    # Insert open ports information
    for port_info in parsed_data['ports_info']:
        cursor.execute('''
            INSERT INTO open_ports (portid, protocol, state, service_name, service_version, host_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (port_info['portid'], port_info['protocol'], port_info['state'],
              port_info['service']['name'], port_info['service']['version'], host_id))

    # Insert traceroute information
    for trace_info in parsed_data['trace_info']:
        cursor.execute('''
            INSERT INTO traceroute (ttl, rtt, address, host_id)
            VALUES (?, ?, ?, ?)
        ''', (trace_info['ttl'], trace_info['rtt'], trace_info['address'], host_id))

    connection.commit()
    connection.close()