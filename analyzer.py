from jinja2 import Environment, FileSystemLoader
import requests
import re
import os
import sqlite3
from lxml import etree
from cve import find_vulnerabilities
from ext import version
from orm import *
from parse_xml import *
from pony.orm import *
from parse_txt import *
from exploit import *
from render import * 
from pprint import pprint
import os
from librairies import *

port_vuln = []
cve_vuln = []

@db_session
def vuln_open_port():
    """
    Query open ports from the first database and check for vulnerabilities
    in the second database. Return a list of dictionaries containing information
    about open ports and associated vulnerabilities.

    Returns:
        List[Dict[str, Union[int, str]]]: A list of dictionaries, each containing
            information about an open port and its associated vulnerabilities.
            Dictionary format: {'port_number': int, 'protocol': str, 'vulnerabilities': str}
    """
    result_list = []

    open_ports = select((p.portid, p.protocol, p.state) for p in Port if p.state == "open")[:]

    for port_info in open_ports:
        port_number, protocol, state = port_info

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
    """
    Parse the content of a file based on its type (txt or xml).

    Args:
        file_path (str): The path to the file.
        file_type (str): The type of the file ('txt' or 'xml').

    Returns:
        Any: The parsed data from the file.

    Raises:
        ValueError: If the file type is not 'txt' or 'xml'.
    """
    with open(file_path, 'r') as file:
        file_content = file.read()

    if file_type == 'txt':
        return parse_txt(file_content)
    elif file_type == 'xml':
        return parse_xml(file_content)
    else:
        raise ValueError(f"Unsupported file type '{file_type}'. Only 'txt' and 'xml' are supported.")

@db_session
def main():
     """
    Main function to collect user input for file paths and types,
    perform database queries, and generate vulnerability reports.

    Raises:
        Exception: Any exception that occurs during the execution of the main function.
    """
    # List of required libraries
    required_libraries = ["searchsploit", "pony.orm", "jinja2", "weasyprint"]
    ask_installation(required_libraries)
    
    num_files = int(input("Enter the number of files: "))
    cve_data = {}
    search = []
    current_directory = os.getcwd()
    html_report_path = os.path.join(current_directory, "vulnerability_report.html")
    pdf_report_path = os.path.join(current_directory, "vulnerability_report.pdf")
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
        service  = service_name + service_version
        if service :
                
                cve_data = find_vulnerabilities(service_name, service_version)
                res = {
                    'service_info': service,
                    'searchsploit_output': run_searchsploit(service_name,  service_version)
                }
                search.append(res)
                

    vuln_data = vuln_open_port()
    generate_html_report(cve_data, vuln_data,search)
    generate_pdf_report(html_report_path, pdf_report_path)


if __name__ == "__main__":
    main()

