import requests
import re
import os
import sqlite3
from jinja2 import Environment, FileSystemLoader
import pdfkit
from lxml import etree
from database_creation import create_database,vulnerabilities_database
port_vuln = []
cve_vuln = []
def parse_txt(nmap_output):
    data = {
        'scan_info': {},
        'host_info': {},
        'ports_info': [],
        'os_info': {},
        'trace_info': []
    }

    lines = nmap_output.split('\n')
    is_traceroute_section = False

    for line in lines:
        line = line.strip()

        if line.startswith("Nmap scan report for"):
            data['host_info']['hostname'] = re.search(r'Nmap scan report for (\S+)', line).group(1)
            data['host_info']['ip_address'] = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line).group(1)

        elif re.match(r'\d+\/tcp', line):
            port_info = line.split()
            port_id = int(port_info[0].split('/')[0])
            protocol = port_info[0].split('/')[1]
            data['ports_info'].append({
                'portid': port_id,
                'protocol': protocol,
                'state': port_info[1],
                'service': {
                    'name': port_info[2],
                    'product': None,
                    'version': ' '.join(port_info[3:])
                }
            })
        elif line.startswith("Device type:"):
            data['os_info']['device_type'] = ' '.join(line.split(':')[1:]).strip()

        elif line.startswith("Running:"):
            data['os_info']['running'] = ' '.join(line.split(':')[1:]).strip()

        elif line.startswith("OS CPE:"):
            data['os_info']['os_cpe'] = ' '.join(line.split(':')[1:]).strip()

        elif line.startswith("OS details:"):
            data['os_info']['os_details'] = ' '.join(line.split(':')[1:]).strip()

        elif line.startswith("TRACEROUTE"):
            is_traceroute_section = True
            continue

        elif is_traceroute_section and line:
            hop_info = line.split()

            try:
                hop = int(hop_info[0])
            except ValueError:
                continue

            data['trace_info'].append({
                'ttl': hop,
                'rtt': hop_info[1],
                'address': hop_info[2]
            })

    return data

def parse_xml(xml_content):
    # Parse the XML content
    root = etree.fromstring(xml_content)

    # Extract information from the XML
    scan_info = {
        'scanner': root.attrib.get('scanner'),
        'args': root.attrib.get('args'),
        'start_time': root.attrib.get('start'),
        'start_time_str': root.attrib.get('startstr'),
        'version': root.attrib.get('version'),
    }

    host_info = {
        'status': root.find('.//host/status').attrib,
        'address': root.find('.//host/address').attrib,
        'hostnames': [hostname.attrib for hostname in root.findall('.//host/hostnames/hostname')],
        'uptime': root.find('.//host/uptime').attrib,
        'distance': root.find('.//host/distance').attrib,
    }

    ports_info = [{
        'portid': port.attrib.get('portid'),
        'protocol': port.attrib.get('protocol'),
        'state': port.find('.//state').attrib,
        'service': {
            'name': port.find('.//service').attrib.get('name'),
            'product': port.find('.//service').attrib.get('product'),
            'version': port.find('.//service').attrib.get('version'),
        },
    } for port in root.findall('.//host/ports/port')]

    os_info = {
        'osclass': [os.attrib for os in root.findall('.//host/os/osclass')],
        'osmatch': [os.attrib for os in root.findall('.//host/os/osmatch')],
    }

    trace_info = [{
        'ttl': hop.attrib.get('ttl'),
        'ipaddr': hop.attrib.get('ipaddr'),
        'rtt': hop.attrib.get('rtt'),
        'host': hop.attrib.get('host'),
    } for hop in root.findall('.//host/trace/hop')]

    runstats_info = {
        'finished': root.find('.//runstats/finished').attrib,
        'hosts': root.find('.//runstats/hosts').attrib,
    }

    return {
        'scan_info': scan_info,
        'host_info': host_info,
        'ports_info': ports_info,
        'os_info': os_info,
        'trace_info': trace_info,
        'runstats_info': runstats_info,
    }
def parse_file(file_path, file_type):
    with open(file_path, 'r') as file:
        file_content = file.read()

    if file_type == 'txt':
        return parse_txt(file_content)
    elif file_type == 'xml':
        return parse_xml(file_content)
    else:
        print(f"Unsupported file type: {file_type}")

def lookup_vulnerabilities(product, version):
    nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {
        'keyword': f"{product} {version}",
        'resultsPerPage': 5,
    }

    response = requests.get(nvd_api_url, params=params)

    if response.status_code == 200:
        vulnerabilities = response.json().get('result', {}).get('CVE_Items', [])
        return [(vuln['cve']['CVE_data_meta']['ID'],
                 vuln['cve']['references']['reference_data'][0]['url'])
                for vuln in vulnerabilities]
    else:
        print(f"Failed to fetch vulnerabilities. Status code: {response.status_code}")
        return []
def open_port_vuln(port, protocol):
    connection = sqlite3.connect('vulnerabilities.db')
    cursor = connection.cursor()

    cursor.execute('''
        SELECT vulnerabilities
        FROM ports
        WHERE port_number = ? AND protocol = ?
    ''', (port, protocol))

    result = cursor.fetchone()

    connection.close()

    return result[0] if result else None


'''def analyze_traceroute(traceroute_data):
    G = nx.Graph()
    for hop in traceroute_data:
        G.add_node(hop['hop'], rtt=hop['rtt'], address=hop['address'])
        if hop['hop'] > 1:
            G.add_edge(hop['hop'], hop['hop'] - 1)
    nx.draw(G, with_labels=True)
    plt.show()
'''
def compare_os(result_id):
    connection = sqlite3.connect('nmap_results.db')
    cursor = connection.cursor()

    # Check if the OS table is filled
    cursor.execute('SELECT COUNT(*) FROM os_info WHERE host_id = ?', (result_id,))
    os_count = cursor.fetchone()[0]

    if os_count > 0:
        print("\nOS details are filled for this result.")
    else:
        print("\nOS details are not filled for this result. Highlighting this!")

    connection.close()

def insert_into_database(parsed_data):
    connection = sqlite3.connect('nmap_results.db')
    cursor = connection.cursor()

    # Insert host information
    cursor.execute('''
        INSERT INTO hosts (hostname, ip_address)
        VALUES (?, ?)
    ''', (parsed_data['host_info']['hostname'], parsed_data['host_info']['ip_address']))

    host_id = cursor.lastrowid  # Get the ID of the last inserted host
    for port_info in parsed_data['ports_info']:
        cursor.execute('''
               INSERT INTO open_ports (portid, protocol, state, service_name, service_version, host_id)
               VALUES (?, ?, ?, ?, ?, ?)
           ''', (port_info['portid'], port_info['protocol'], port_info['state'],
                 port_info['service']['name'], port_info['service']['version'], host_id))

        if port_info['state'] == 'open':
            vulnerabilities = open_port_vuln(port_info['portid'], port_info['protocol'])
            if vulnerabilities:
                # Store vulnerabilities in a list for further use if needed
                port_vuln.append((port_info['portid'], vulnerabilities))

    os_info = parsed_data.get('os_info', {})
    cursor.execute('''
            INSERT INTO os_info (device_type, running, os_cpe, os_details, host_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (os_info.get('device_type'), os_info.get('running'), os_info.get('os_cpe'),
              os_info.get('os_details'), host_id))

    # Insert traceroute information
    for trace_info in parsed_data['trace_info']:
        cursor.execute('''
            INSERT INTO traceroute (ttl, rtt, address, host_id)
            VALUES (?, ?, ?, ?)
        ''', (trace_info['ttl'], trace_info['rtt'], trace_info['address'], host_id))

    connection.commit()
    connection.close()
def generate_reports():
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('template.html')

    # Render the template with data
    html_content = template.render(port_vuln=port_vuln, cve_vuln=cve_vuln)

    # Save the HTML content to a file
    with open('report.html', 'w', encoding='utf-8') as html_file:
        html_file.write(html_content)

    # Convert HTML to PDF
    pdfkit.from_file('report.html', 'report.pdf')
    pass
def main():
    num_files = int(input("Enter the number of files: "))

    vulnerabilities_database()

    for i in range(num_files):
        file_path = input(f"Enter the path for file {i + 1}: ")
        file_type = input(f"Enter the file type for file {i + 1} (txt or xml): ").lower()


        parsed_data = parse_file(file_path, file_type)
        create_database()
        insert_into_database(parsed_data)

        for port_info in parsed_data['ports_info']:
            if 'service' in port_info:
                product = port_info['service']['name']
                version = port_info['service']['version']
                vulnerabilities = lookup_vulnerabilities(product, version)

                for vuln_id, vuln_url in vulnerabilities:
                    cve_vuln.append({
                        'vulnerability_id': vuln_id,
                        'url': vuln_url,
                        'product': product,
                        'version': version
                    })
    generate_reports()

if __name__ == "__main__":
    main()