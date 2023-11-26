import requests

def find_vulnerabilities(product_names):
    vulnerabilities_by_product = {}

    for product_name in product_names:
        if product_name is None:
            continue

        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        encoded_product_name = product_name.replace(" ", "%20")
        search_url = f"{base_url}?keywordSearch={encoded_product_name}"

        response = requests.get(search_url)

        if response.status_code == 200:
            cve_data = response.json()
            total_results = cve_data.get('totalResults', 0)

            if total_results > 0:
                vulnerabilities = []
                for result in cve_data['vulnerabilities']:
                    cve_id = result['cve']['id']
                    cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    vulnerabilities.append({'cve_id': cve_id, 'cve_url': cve_url})

                vulnerabilities_by_product[product_name] = vulnerabilities

    return vulnerabilities_by_product
