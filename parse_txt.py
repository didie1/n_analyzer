import re 
from pprint import pprint

def parse_version(version_info):
    """
    Parse version information to extract the product and version.

    Args:
        version_info (str): The version information to parse.

    Returns:
        dict: A dictionary containing 'product' and 'version' keys.
            - 'product' (str): The parsed product name.
            - 'version' (str): The parsed version.

    Notes:
        - If the product or version cannot be extracted, default values of 'Unknown' are provided.
    """
    # Use a regular expression to extract the product and version
    match = re.match(r'^([^\d]+)\s*([\d.]+)?', version_info)
    if match:
        product = match.group(1).strip().split()[0] if match.group(1) else "Unknown"  # Extracting the first word; Default to "Unknown" if product is None
        version = match.group(2).strip() if match.group(2) else "Unknown"  # Default to "Unknown" if version is None
        return {'product': product, 'version': version}
    else:
        return {'product': "Unknown", 'version': "Unknown"}

def parse_txt(nmap_output):
    """
    Parse Nmap scan output in text format.

    Args:
        nmap_output (str): The Nmap scan output in text format.

    Returns:
        dict: A dictionary containing parsed information with the following structure:
            {
                'scan_info': {},
                'host_info': {
                    'hostname': str,
                    'ip_address': str
                },
                'ports_info': [
                    {
                        'portid': int,
                        'protocol': str,
                        'state': str,
                        'service': {
                            'name': str,
                            'product': str,
                            'version': str
                        }
                    },
                    # Additional port entries if present
                ],
                'os_info': {
                    'device_type': str,
                    'running': str,
                    'os_cpe': str,
                    'os_details': str
                },
                'trace_info': [
                    {
                        'ttl': int,
                        'rtt': str,
                        'address': str
                    },
                    # Additional traceroute entries if present
                ]
            }

    Notes:
        - Default values of 'Unknown' are provided for missing keys.
    """ 
    data = {
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

            version_info = ' '.join(port_info[3:])
            version_data = parse_version(version_info)

            data['ports_info'].append({
                'portid': port_id,
                'protocol': protocol,
                'state': port_info[1],
                'service': {
                    'name': port_info[2],
                    'product': version_data['product'],
                    'version': version_data['version']
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

    # Provide default values if the keys are not present
    data['os_info'].setdefault('device_type', 'Unknown')
    data['os_info'].setdefault('running', 'Unknown')
    data['os_info'].setdefault('os_cpe', 'Unknown')
    data['os_info'].setdefault('os_details', 'Unknown')
    return data

