from jinja2 import Template
import subprocess
import requests
import weasyprint 
import requests
def generate_html_report(vulnerabilities_by_product, open_ports_vulnerabilities, run_exploit_results):
    with open("template.html", "r") as template_file:
        template_content = template_file.read()

    template = Template(template_content)
    rendered_html = template.render(vulnerabilities_by_product=vulnerabilities_by_product,
                                   open_ports_vulnerabilities=open_ports_vulnerabilities,
                                   run_exploit_results=run_exploit_results)

    with open("vulnerability_report.html", "w") as report_file:
        report_file.write(rendered_html)
def generate_pdf_report(html_file, pdf_file):
    # Generate PDF from HTML using WeasyPrint
    weasyprint.HTML(string=open(html_file).read()).write_pdf(pdf_file)
