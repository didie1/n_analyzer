import xml.etree.ElementTree as ET
from pprint import pprint
import re
def parse_xml(xml_content):
    """
    This function scan results from a nmap scan and extract information about hosts and open ports.

    Parameters:
    - xml_content (str): The XML content of the Nmap scan results.

    Returns:
    - list: A list of dictionaries, each containing information about a host:
        [
            {
                'address': str,         # IP address of the host
                'hostname': str,        # Hostname of the host
                'ports': [
                    {
                        'protocol': str,    # Protocol of the open port (e.g., 'tcp')
                        'portid': str,      # Port number or range (e.g., '22' or '1-1000')
                        'state': str,       # State of the port (e.g., 'open', 'closed')
                        'service': str,     # Service name (e.g., 'ssh', 'http')
                        'product': str,     # Product name (extracted from service information)
                        'version': str      # Version number (extracted from service information)
                    },
                    # ... (additional ports)
                ]
            },
            # ... (additional hosts)
        ]
    """
    root = ET.fromstring(xml_content)

    hosts = []
    for host in root.findall(".//host"):
        host_info = {
            'address': host.find("address").attrib['addr'],
            'hostname': host.find("hostnames/hostname").attrib['name'],
            'ports': []
        }
        for port in host.findall("ports/port"):
            port_info = {
                'protocol': port.attrib['protocol'],
                'portid': port.attrib['portid'],
                'state': port.find("state").attrib['state'],
                'service': port.find("service").attrib['name'],
                'product': 'Unknown',
                'version': 'Unknown'
            }

            # Extract product and version information if available
            service_elem = port.find("service")
            if 'product' in service_elem.attrib:
                # Strip the product by space and take the first word
                port_info['product'] = service_elem.attrib['product'].split(' ')[0]
            if 'version' in service_elem.attrib:
                # Use regex to extract only X.X or X.X.X versions
                version_match = re.match(r'(\d+\.\d+(\.\d+)?)', service_elem.attrib['version'])
                if version_match:
                    port_info['version'] = version_match.group(1)

            host_info['ports'].append(port_info)

        hosts.append(host_info)

    return hosts

