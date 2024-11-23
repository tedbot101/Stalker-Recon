import requests
import json
import argparse

def get_subdomains_crtsh(domain):
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

    return subdomains

def get_subdomains_certspotter(domain):
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

    return subdomains

def save_to_file(filename, subdomains):
    with open(filename, 'w') as f:
        for subdomain in sorted(subdomains):
            f.write(subdomain + '\n')

def main():
    parser = argparse.ArgumentParser(description="Enumerate subdomains using crt.sh and CertSpotter")
    parser.add_argument('-d', '--domain', required=True, help='Domain to enumerate subdomains for')
    args = parser.parse_args()

    subdomains_crtsh = get_subdomains_crtsh(args.domain)
    subdomains_certspotter = get_subdomains_certspotter(args.domain)

    all_subdomains = subdomains_crtsh.union(subdomains_certspotter)

    if all_subdomains:
        save_to_file('all_subdomains.txt', all_subdomains)
        print(f"Subdomains found for {args.domain} have been saved to all_subdomains.txt")
    else:
        print(f"No subdomains found for {args.domain}.")

if __name__ == "__main__":
    main()