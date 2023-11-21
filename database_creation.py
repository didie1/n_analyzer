import sqlite3
from analyzer import lookup_vulnerabilities
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
            CREATE TABLE IF NOT EXISTS os_info (
                id INTEGER PRIMARY KEY,
                device_type TEXT,
                running TEXT,
                os_cpe TEXT,
                os_details TEXT,
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


def vulnerabilities_database():
    connection = sqlite3.connect('vulnerabilities.db')
    cursor = connection.cursor()

    # Create a table for ports
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY,
            port_number INTEGER,
            protocol TEXT,
            description TEXT,
            vulnerabilities TEXT
        )
    ''')

    # Insert data into the ports table
    ports_data = [
        (20, 'FTP', 'File Transfer Protocol', 'Brute-forcing passwords, anonymous authentication, cross-site scripting, directory traversal attacks.'),
        (21, 'FTP', 'File Transfer Protocol', 'Brute-forcing passwords, anonymous authentication, cross-site scripting, directory traversal attacks.'),
        (22, 'SSH', 'Secure Shell', 'Exploited using leaked SSH keys, brute-forcing credentials.'),
        (23, 'Telnet', 'Remote Computer Connections', 'Outdated and insecure, susceptible to credential brute-forcing, spoofing, and credential sniffing.'),
        (25, 'SMTP', 'Simple Mail Transfer Protocol', 'Spoofing and spamming without proper configuration and protection.'),
        (53, 'DNS', 'Domain Name System', 'Vulnerable to DDoS attacks.'),
        (137, 'NetBIOS', 'NetBIOS over TCP', 'Exploited using EternalBlue, capturing NTLM hashes, brute-forcing SMB login credentials.'),
        (139, 'NetBIOS', 'NetBIOS over TCP', 'Exploited using EternalBlue, capturing NTLM hashes, brute-forcing SMB login credentials.'),
        (445, 'SMB', 'Server Message Block', 'Exploited using EternalBlue, capturing NTLM hashes, brute-forcing SMB login credentials.'),
        (80, 'HTTP', 'Hypertext Transfer Protocol', 'Vulnerable to cross-site scripting, SQL injections, cross-site request forgeries, and DDoS attacks.'),
        (443, 'HTTPS', 'Hypertext Transfer Protocol Secure', 'Vulnerable to cross-site scripting, SQL injections, cross-site request forgeries, and DDoS attacks.'),
        (8080, 'HTTP', 'Hypertext Transfer Protocol', 'Vulnerable to cross-site scripting, SQL injections, cross-site request forgeries, and DDoS attacks.'),
        (8443, 'HTTPS', 'Hypertext Transfer Protocol Secure', 'Vulnerable to cross-site scripting, SQL injections, cross-site request forgeries, and DDoS attacks.'),
        (1433, 'SQL', 'SQL Server', 'Used to distribute malware or directly attacked in DDoS scenarios, probed for unprotected databases with exploitable default configurations.'),
        (1434, 'SQL', 'SQL Server', 'Used to distribute malware or directly attacked in DDoS scenarios, probed for unprotected databases with exploitable default configurations.'),
        (3306, 'SQL', 'MySQL', 'Used to distribute malware or directly attacked in DDoS scenarios, probed for unprotected databases with exploitable default configurations.'),
        (3389, 'RDP', 'Remote Desktop Protocol', 'Probed for leaked or weak user authentication, commonly exploited (e.g., BlueKeep vulnerability).')
    ]

    cursor.executemany('''
        INSERT INTO ports (port_number, protocol, description, vulnerabilities)
        VALUES (?, ?, ?, ?)
    ''', ports_data)

    connection.commit()
    connection.close()
