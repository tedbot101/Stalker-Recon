import requests
import json
import argparse
from datetime import datetime

def get_subdomains_crtsh(domain):
    print("Fetching data from crt.sh...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url)
    
    if response.status_code != 200:
        print(f"Error fetching data from crt.sh: {response.status_code}")
        return []

    subdomains = set()
    try:
        certs = json.loads(response.text)
        for cert in certs:
            name_value = cert.get('name_value')
            if name_value:
                subdomains.update(name_value.split('\n'))
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}")
        return []

    print(f"Found {len(subdomains)} subdomains from crt.sh.")
    return subdomains

def get_subdomains_certspotter(domain):
    print("Fetching data from CertSpotter...")
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    response = requests.get(url)
    
    if response.status_code != 200:
        print(f"Error fetching data from CertSpotter: {response.status_code}")
        return []

    subdomains = set()
    try:
        certs = json.loads(response.text)
        for cert in certs:
            dns_names = cert.get('dns_names', [])
            subdomains.update(dns_names)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}")
        return []

    print(f"Found {len(subdomains)} subdomains from CertSpotter.")
    return subdomains

def save_to_file(filename, crtsh_subdomains, certspotter_subdomains):
    data = {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": {
            "crtsh": sorted(crtsh_subdomains),
            "certspotter": sorted(certspotter_subdomains)
        }
    }
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Enumerate subdomains using crt.sh and CertSpotter")
    parser.add_argument('-d', '--domain', required=True, help='Domain to enumerate subdomains for')
    args = parser.parse_args()

    subdomains_crtsh = get_subdomains_crtsh(args.domain)
    subdomains_certspotter = get_subdomains_certspotter(args.domain)

    if subdomains_crtsh or subdomains_certspotter:
        save_to_file('all_subdomains.json', subdomains_crtsh, subdomains_certspotter)
        print(f"Subdomains found for {args.domain} have been saved to all_subdomains.json")
    else:
        print(f"No subdomains found for {args.domain}.")

if __name__ == "__main__":
    main()