from jinja2 import Template
import os
import weasyprint

def generate_html_report(vulnerabilities_by_product, open_ports_vulnerabilities, run_exploit_results):
    """
    Generate an HTML report based on the provided data.

    Parameters:
    - vulnerabilities_by_product (dict): A dictionary containing vulnerabilities information for each product.
    - open_ports_vulnerabilities (list): A list of dictionaries containing information about open ports vulnerabilities.
    - run_exploit_results (str): A string containing the results of the exploit search.

    Output:
    - Creates an HTML file named "vulnerability_report.html" with the rendered report in the current working directory.
    """
    current_directory = os.getcwd()
    html_file_path = os.path.join(current_directory, "vulnerability_report.html")

    with open("template.html", "r") as template_file:
        template_content = template_file.read()

    template = Template(template_content)
    rendered_html = template.render(vulnerabilities_by_product=vulnerabilities_by_product,
                                   open_ports_vulnerabilities=open_ports_vulnerabilities,
                                   run_exploit_results=run_exploit_results)

    with open(html_file_path, "w") as report_file:
        report_file.write(rendered_html)

def generate_pdf_report(html_file_name="vulnerability_report.html", pdf_file_name="vulnerability_report.pdf"):
    """
    Generate a PDF report from an HTML file using WeasyPrint.

    Parameters:
    - html_file_name (str): The name of the HTML file to be converted to PDF. Default is "vulnerability_report.html".
    - pdf_file_name (str): The name of the resulting PDF file. Default is "vulnerability_report.pdf".

    Output:
    - Creates a PDF file with the specified name in the current working directory.
    """
    current_directory = os.getcwd()
    html_file_path = os.path.join(current_directory, html_file_name)
    pdf_file_path = os.path.join(current_directory, pdf_file_name)

    # Generate PDF from HTML using WeasyPrint
    weasyprint.HTML(string=open(html_file_path).read()).write_pdf(pdf_file_path)
