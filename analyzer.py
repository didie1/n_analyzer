import requests
import re
import os
import sqlite3
from lxml import etree
from database_creation import create_database, insert_into_database

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

def analyze_traceroute(traceroute_data):
    G = nx.Graph()
    for hop in traceroute_data:
        G.add_node(hop['hop'], rtt=hop['rtt'], address=hop['address'])
        if hop['hop'] > 1:
            G.add_edge(hop['hop'], hop['hop'] - 1)
    nx.draw(G, with_labels=True)
    plt.show()




def generate_reports(vulnerability_data):
    # Your code to generate HTML and PDF reports using vulnerability_data
    pass
def main():
    num_files = int(input("Enter the number of files: "))
    vulnerability_data = []
    for i in range(num_files):
        file_path = input(f"Enter the path for file {i + 1}: ")
        file_type = input(f"Enter the file type for file {i + 1} (txt or xml): ").lower()

        # Call the appropriate parsing function based on file type
        parsed_data = parse_file(file_path, file_type)
        create_database()
        insert_into_database(parsed_data)

        # Example usage of lookup_vulnerabilities
        for port_info in parsed_data['ports_info']:
            if 'service' in port_info:
                product = port_info['service']['name']
                version = port_info['service']['version']
                vulnerabilities = lookup_vulnerabilities(product, version)

                for vuln_id, vuln_url in vulnerabilities:
                    vulnerability_data.append({
                        'vulnerability_id': vuln_id,
                        'url': vuln_url,
                        'product': product,
                        'version': version
                    })

if __name__ == "__main__":
    main()