from pony.orm import *

db = Database("sqlite", ":memory:")

class Host(db.Entity):
    id = PrimaryKey(int, auto=True)
    hostname = Required(str)
    ip_address = Required(str)
    open_ports = Set("Port")
    os_info = Set("OSInfo")
    traceroutes = Set("Traceroute")

class Port(db.Entity):
    id = PrimaryKey(int, auto=True)
    portid = Required(int)
    protocol = Required(str)
    state = Required(str)
    service_name = Optional(str)
    service_version = Optional(str)
    host = Required(Host)

class OSInfo(db.Entity):
    id = PrimaryKey(int, auto=True)
    device_type = Optional(str)
    running = Optional(str)
    os_cpe = Optional(str)
    os_details = Optional(str)
    host = Required(Host)

class Traceroute(db.Entity):
    id = PrimaryKey(int, auto=True)
    ttl = Optional(int)
    rtt = Optional(str)
    address = Optional(str)
    host = Required(Host)

# Define the Pony ORM database entity for the vulnerabilities database
vulnerabilities_db = Database("sqlite", ":memory:")

class Vulnerability(vulnerabilities_db.Entity):
    id = PrimaryKey(int, auto=True)
    port_number = Required(int)
    protocol = Required(str)
    description = Required(str)
    vulnerabilities = Required(str)

# Generate the mapping and create the table
vulnerabilities_db.generate_mapping(create_tables=True)

@db_session
def vulnerabilities_database():
    """
    Inserts predefined vulnerability data into the vulnerabilities table.

    This function populates the vulnerabilities table with pre-defined data
    regarding ports, protocols, descriptions, and potential vulnerabilities.

    :return: None
    """
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

    for port_data in ports_data:
        Vulnerability(
            port_number=port_data[0],
            protocol=port_data[1],
            description=port_data[2],
            vulnerabilities=port_data[3]
        )


@db_session
def query_open_ports():
    """
    Queries and returns a list of open ports from the Port table.

    :return: List of open ports (Port instances)
    """
    open_ports = Port.select(lambda op: op.state == "open")[:]
    return open_ports

@db_session
def query_vulnerabilities(port_number, protocol):
    """
    Queries and returns information about vulnerabilities for a specific port and protocol.

    :param port_number: The port number to query vulnerabilities for.
    :param protocol: The protocol associated with the port.
    :return: Vulnerability information (Vulnerability instance) or None if not found.
    """
    vulnerabilities_info = Vulnerability.get(port_number=port_number, protocol=protocol)
    return vulnerabilities_info


@db_session
def insert_txt(parsed_data):
    """
    Inserts parsed data into the database using Pony ORM.

    This function takes parsed data, including information about the host, open ports, OS details,
    and traceroute data, and inserts it into the database using the Pony ORM.

    :param parsed_data: Parsed data containing information about the scan.
    :return: None
    """
    # Insert data for Host
    host = Host(
        hostname=parsed_data['host_info'].get('hostname'),
        ip_address=parsed_data['host_info'].get('ip_address')
    )

    # Insert data for OpenPorts
    for port_info in parsed_data['ports_info']:
        open_port = Port(
            portid=port_info['portid'],
            protocol=port_info['protocol'],
            state=port_info['state'],
            service_name=port_info['service']['name'],
            service_version=port_info['service']['version'],
            host=host
        )

    # Insert data for OSInfo
    os_info_data = parsed_data.get('os_info', {})
    os_info = OSInfo(
        device_type=os_info_data.get('device_type', 'Unknown'),
        running=os_info_data.get('running', 'Unknown'),
        os_cpe=os_info_data.get('os_cpe', 'Unknown'),
        os_details=os_info_data.get('os_details', 'Unknown'),
        host=host
    )

    # Insert data for Traceroutes
    for trace_info in parsed_data['trace_info']:
        traceroute = Traceroute(
            ttl=trace_info['ttl'],
            rtt=trace_info['rtt'],
            address=trace_info['address'],
            host=host
        )

@db_session
def insert_xml(data):
    """
    Inserts XML data into the database using Pony ORM.

    This function takes XML data, including information about hosts and their associated ports,
    and inserts it into the database using the Pony ORM.

    :param data: XML data containing information about hosts and ports.
    :return: None
    """
    for host in data:
        host_info = Host(hostname=host['hostname'], ip_address=host['address'])
        for port in host['ports']:
            Port(portid=port['portid'], protocol=port['protocol'], state=port['state'],
                 service_name=port['service'], service_version="", host=host_info)

@db_session
def get_service():
    """
    Retrieves and returns service information from the Port table.

    :return: List of tuples containing service name and version information.
    """
    return select((p.service_name, p.service_version) for p in Port)

#Generate the mapping and create tables
db.generate_mapping(create_tables=True)

