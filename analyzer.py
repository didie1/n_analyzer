from jinja2 import Environment, FileSystemLoader
import requests
import re
import os
import sqlite3
from lxml import etree
from cve import find_vulnerabilities
from ext import version
from database_creation import create_database,vulnerabilities_database
from orm import *
from parse_xml import *
from pony.orm import *
from parse_txt import *
port_vuln = []
cve_vuln = []

def render_html(template_name, context):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template(template_name)
    return template.render(context)
'''@db_session
def vuln_open_port():
    # Query open ports from the first database
    open_ports = select((p.portid, p.protocol, p.state) for p in Port if p.state == "open")[:]
    result_dict = []

    # Iterate through open ports and check against vulnerabilities database
    for port_info in open_ports:
        port_number, protocol, state = port_info

        # Query vulnerabilities information for the current port from the second database
        vulnerabilities_info = select((v.description, v.vulnerabilities) for v in Vulnerability if v.port_number == port_number).first()
        if vulnerabilities_info:
            description, vulnerabilities = vulnerabilities_info
            result_dict[f"{port_number}/{protocol}"] = {
                'description': description,
                'vulnerabilities': vulnerabilities
            }

    return result_dict'''
@db_session
def vuln_open_port():
    result_list = []

    # Query open ports from the first database
    open_ports = select((p.portid, p.protocol, p.state) for p in Port if p.state == "open")[:]

    # Iterate through open ports and check against vulnerabilities database
    for port_info in open_ports:
        port_number, protocol, state = port_info

        # Query vulnerabilities information for the current port from the second database
        vulnerabilities_info = select((v.description, v.vulnerabilities) for v in Vulnerability if v.port_number == port_number).first()

        if vulnerabilities_info:
            description, vulnerabilities = vulnerabilities_info
            result_list.append({
                'port_number': port_number,
                'protocol': protocol,
                'vulnerabilities': vulnerabilities
            })

    return result_list

def parse_file(file_path, file_type):
    with open(file_path, 'r') as file:
        file_content = file.read()

    if file_type == 'txt':
        return parse_txt(file_content)
    else:
        return parse_xml(file_content)

def compare(result_id):
    connection = sqlite3.connect('nmap_results.db')
    cursor = connection.cursor()

    # Check if the OS table is filled
    cursor.execute('SELECT COUNT(*) FROM os_info WHERE host_id = ?', (result_id,))
    os_count = cursor.fetchone()[0]

    if os_count > 0:
        print("\nOS details are filled for this result.")
    else:
        print("\n NO luck")

    connection.close()

def generate_reports():
   pass
@db_session
def main():
    num_files = int(input("Enter the number of files: "))

    vulnerabilities_database()
    cve_data = {}
    create_database()
    for i in range(num_files):
        file_path = input(f"Enter the path for file {i + 1}: ")
        file_type = input(f"Enter the file type for file {i + 1} (txt or xml): ").lower()


        parsed_data = parse_file(file_path, file_type)
        if file_type == "txt":
            insert_txt(parsed_data)
        else : 
            insert_xml(parsed_data)
        service_info_query = get_service()
        for service_info in service_info_query:
            service_name, service_version = service_info
            service  = version(service_version)
            if service :
                cve_data = find_vulnerabilities(service)
    vuln_data = vuln_open_port()
    context = {
        'port_vuln': vuln_data,
        'cve_vuln': cve_data
        # Add other data to the context dictionary if needed
    }

    # Render the HTML using the template
    rendered_html = render_html('template.html', context)

    # Save the rendered HTML to a file
    with open('report.html', 'w', encoding='utf-8') as file:
        file.write(rendered_html)

if __name__ == "__main__":
    main()

