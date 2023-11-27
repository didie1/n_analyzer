def find_vulnerabilities(product, version):
    """
    Fetch vulnerabilities data from the NIST National Vulnerability Database (NVD) based on a product and version.

    Args:
        product (str): The name of the product.
        version (str): The version of the product.

    Returns:
        dict: A dictionary containing vulnerabilities data with the following structure:

            {
                'product version': [
                    {
                        'cve_id': str,      # Common Vulnerabilities and Exposures (CVE) identifier
                        'cve_url': str      # URL to the CVE details on the NVD website
                    },
                    # Additional CVE entries if present
                ]
            }

        An empty dictionary is returned if no vulnerabilities are found or if the product or version is 'Unknown'.

    Notes:
        - The function makes requests to the NVD RESTful API to retrieve vulnerability information.
        - If the product or version is 'Unknown', a log entry is created, and the function returns an empty dictionary.
        - The function retries in case of a 403 Forbidden response, with an increasing delay between retries.
        - If the maximum number of retries is reached, the function logs an error and returns the HTTP status code.
    """
    if product == 'Unknown' or version == 'Unknown':
        logging.info("Product name or version is 'Unknown'. Skipping request.")
        return {}

    product_name = f"{product} {version}"
    vulnerabilities_by_product = {}
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    encoded_product_name = product_name.replace(" ", "%20")
    search_url = f"{base_url}?keywordSearch={encoded_product_name}"

    max_retries = 3
    retry_delay = 15  # in seconds

    for attempt in range(1, max_retries + 1):
        response = requests.get(search_url)

        if response.status_code == 200:
            cve_data = response.json()
            total_results = cve_data.get('totalResults', 0)

            if total_results > 0:
                vulnerabilities = []
                for result in cve_data['result']['CVE_Items']:
                    cve_id = result['cve']['CVE_data_meta']['ID']
                    cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    vulnerabilities.append({'cve_id': cve_id, 'cve_url': cve_url})

                vulnerabilities_by_product[product_name] = vulnerabilities
                return vulnerabilities_by_product
            else:
                return vulnerabilities_by_product
        elif response.status_code == 403 and attempt < max_retries:
            logging.warning(f"Forbidden. Retrying attempt {attempt} in {retry_delay} seconds...")
            time.sleep(retry_delay)
            retry_delay *= 2
        else:
            logging.error(f"Failed to fetch data. Status code: {response.status_code}")
            return response.status_code

    return vulnerabilities_by_product

