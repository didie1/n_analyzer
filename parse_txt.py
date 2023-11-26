import re 
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

    # Provide default values if the keys are not present
    data['os_info'].setdefault('device_type', 'Unknown')
    data['os_info'].setdefault('running', 'Unknown')
    data['os_info'].setdefault('os_cpe', 'Unknown')
    data['os_info'].setdefault('os_details', 'Unknown')
    return data

