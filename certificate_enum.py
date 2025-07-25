import requests
import json
import argparse
from datetime import datetime
import httpx
import asyncio

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

def combine_and_clean_subdomains(crtsh_subdomains, certspotter_subdomains):
    combined_subdomains = crtsh_subdomains.union(certspotter_subdomains)
    
    # Remove wildcard domains and duplicates
    cleaned_subdomains = {sub for sub in combined_subdomains if '*' not in sub}
    
    return cleaned_subdomains

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

async def check_liveliness(subdomain, ports, rate_limit, proxy, user_agent):
    results = []
    async with httpx.AsyncClient( headers={"User-Agent": user_agent}) as client:
        for port in ports:
            url = f"http://{subdomain}:{port}"
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    results.append({"url": url, "status": "live", "status_code": response.status_code})
                    print(f"{url} is live with status code {response.status_code}")
                else:
                    results.append({"url": url, "status": f"status code {response.status_code}", "status_code": response.status_code})
                    print(f"{url} returned status code {response.status_code}")
            except httpx.RequestError as exc:
                results.append({"url": url, "status": f"could not be reached: {exc}", "status_code": None})
                print(f"{url} could not be reached: {exc}")
            await asyncio.sleep(1 / rate_limit)
    return results

async def main():
    parser = argparse.ArgumentParser(description="Enumerate subdomains using crt.sh and CertSpotter")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Domain to enumerate subdomains for')
    group.add_argument('-D', '--domain-file', help='File with list of domains to enumerate')
    parser.add_argument('--ports', nargs='+', type=int, default=[8443, 443, 80], 
                        help='Ports to check for liveliness (default: 8443, 443, 80)')
    parser.add_argument('--rate-limit', type=float, default=3.0, 
                        help='Rate limit for liveliness checks (requests per second, default: 3)')
    parser.add_argument('--proxy', type=str, default=None, 
                        help='Proxy to use for liveliness checks (e.g., http://yourproxy:port)')
    parser.add_argument('--user-agent', type=str, 
                        default="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/113.0", 
                        help='User-Agent to use for liveliness checks (default: Mozilla/5.0...)')
    parser.add_argument('--debug', action='store_true', help='Save all results including unreachable hosts')

    args = parser.parse_args()

    if args.domain_file:
        with open(args.domain_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        domains = [args.domain]

    for domain in domains:
        print(f"\n=== Enumerating subdomains for {domain} ===")
        subdomains_crtsh = get_subdomains_crtsh(domain)
        subdomains_certspotter = get_subdomains_certspotter(domain)

        if subdomains_crtsh or subdomains_certspotter:
            filename = f'{domain}_all_subdomains.json'
            save_to_file(filename, subdomains_crtsh, subdomains_certspotter)
            print(f"Subdomains saved to {filename}")

            combined_cleaned_subdomains = combine_and_clean_subdomains(subdomains_crtsh, subdomains_certspotter)

            tasks = [check_liveliness(subdomain, args.ports, args.rate_limit, args.proxy, args.user_agent)
                     for subdomain in combined_cleaned_subdomains]
            results = await asyncio.gather(*tasks)

            flat_results = [item for sublist in results for item in sublist]

            if not args.debug:
                flat_results = [result for result in flat_results if result['status'] == 'live']

            result_filename = f'{domain}_liveliness_check_results.json'
            with open(result_filename, 'w') as f:
                json.dump(flat_results, f, indent=4)
            print(f"Liveliness results saved to {result_filename}")
        else:
            print(f"No subdomains found for {domain}.")

if __name__ == "__main__":
    asyncio.run(main())