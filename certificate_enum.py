import requests
import json
import argparse
import time
import logging
import httpx
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(filename='api_errors.log', level=logging.ERROR)

# Define your API keys and endpoints
API_KEYS = {
    'censys': os.getenv('CENSYS_API_KEYS').split(','),
    'certspotter': os.getenv('CERTSPOTTER_API_KEYS').split(','),
    'certcentral': os.getenv('CERTCENTRAL_API_KEYS').split(','),
    'crtsh': os.getenv('CRTSH_API_KEYS').split(','),
    'digitorus': os.getenv('DIGITORUS_API_KEYS').split(','),
    'facebookct': os.getenv('FACEBOOK_CT_API_KEYS').split(','),
    'virustotal': os.getenv('VIRUSTOTAL_API_KEYS').split(','),
    'passivetotal': os.getenv('PASSIVETOTAL_API_KEYS').split(','),
}

# Rate limits (requests per minute)
RATE_LIMITS = {
    'censys': 10,
    'certspotter': 75,
    'certcentral': 1000 / 3,
    'virustotal': 4,
    'passivetotal': 100,
}

# Track requests made
request_count = {key: 0 for key in RATE_LIMITS.keys()}
api_key_index = {key: 0 for key in API_KEYS.keys()}

def get_next_api_key(service):
    keys = API_KEYS[service]
    index = api_key_index[service]
    api_key_index[service] = (index + 1) % len(keys)
    return keys[index]

def check_rate_limit(service):
    if request_count[service] >= RATE_LIMITS[service]:
        print(f"Rate limit reached for {service}. Waiting for reset...")
        time.sleep(60)
        request_count[service] = 0

def check_response(response, service):
    if response.status_code == 429:
        retry_after = int(response.headers.get('Retry-After', 60))
        print(f"Rate limit exceeded for {service}. Retrying after {retry_after} seconds.")
        time.sleep(retry_after)
        return None
    elif response.status_code != 200:
        error_message = f"Error from {service}: Received status code {response.status_code} - {response.text}"
        print(error_message)
        log_error(error_message)
        return None
    return response.json()

def log_error(message):
    logging.error(message)

def log_debug(debug_info):
    with open('debug.txt', 'a') as debug_file:
        json.dump(debug_info, debug_file, indent=4)
        debug_file.write('\n')

def query_with_retry(url, headers, params, service, retries=3):
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, params=params)
            debug_info = {
                "attempt": attempt + 1,
                "service": service,
                "url": url,
                "params": params,
                "status_code": response.status_code
            }
            log_debug(debug_info)
            result = check_response(response, service)
            if result is not None:
                return result
        except requests.exceptions.RequestException as e:
            error_message = f"Request failed for {service}: {e}"
            print(error_message)
            log_error(error_message)
            time.sleep(2)
    return None

def query_api(service, domain, user_agent):
    check_rate_limit(service)
    url_map = {
        'censys': f'https://censys.io/api/v1/search/ipv4',
        'certspotter': f'https://api.certspotter.com/v1/issuances',
        'crtsh': f'https://crt.sh/?q={domain}&output=json',
        'digitorus': f'https://api.digitorus.com/v1/subdomains/{domain}',
        'facebookct': f'https://facebook.com/certificate-transparency/api/v1/entries',
        'virustotal': f'https://www.virustotal.com/api/v3/domains/{domain}',
        'passivetotal': f'https://api.passivetotal.org/v2/enrichment'
    }
    
    headers = {'User-Agent': user_agent}
    api_key = get_next_api_key(service)
    if service == 'censys':
        headers['Authorization'] = f'Basic {api_key}'
    elif service == 'digitorus':
        headers['Authorization'] = f'Bearer {api_key}'
    elif service == 'virustotal':
        headers['x-apikey'] = api_key
    elif service == 'passivetotal':
        headers['Authorization'] = f'ApiKey {api_key}'
        headers['Content-Type'] = 'application/json'

    return query_with_retry(url_map[service], headers, {'domain': domain}, service)

def extract_endpoints(data):
    endpoints = set()
    if isinstance(data, list):
        for item in data:
            endpoints.add(item.get('name'))
    elif isinstance(data, dict):
        endpoints.add(data.get('name'))
    return endpoints

def live_check(targets, ports, user_agent, proxy):
    results = {}
    for target in targets:
        results[target] = {}
        for port in ports:
            url = f"http://{target}:{port}"
            try:
                response = httpx.get(url, headers={'User-Agent': user_agent}, proxies=proxy, timeout=5)
                results[target][port] = {
                    "status_code": response.status_code,
                    "title": response.html.title if response.status_code == 200 else None
                }
            except Exception as e:
                results[target][port] = {"error": str(e)}
    return results

def main(domain, output_file, output_format, debug, user_agent, live_check_flag, proxy, additional_ports):
    default_ports = [80, 443, 8443]
    ports_to_check = default_ports + additional_ports

    results = {
        "found": {},
        "endpoints": set()
    }

    for service in ['censys', 'certspotter', 'crtsh', 'digitorus', 'facebookct', 'virustotal', 'passivetotal']:
        data = query_api(service, domain, user_agent)
        if data is None:
            print(f"Failed to retrieve data from {service}. Check logs for details.")
        else:
            results["found"][service] = data
            results["endpoints"].update(extract_endpoints(data))

    if live_check_flag:
        targets = list(results["endpoints"])
        live_results = live_check(targets, ports_to_check, user_agent, proxy)
        results["live_check"] = live_results

    output_data = results if output_format == "1" else {"endpoints": list(results["endpoints"])}

    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=4)
    print(f"Results saved to {output_file}")

    if debug:
        log_debug({"results": output_data})
        print("Debug information saved to debug.txt.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Enumerate subdomains and endpoints. Some options are only allowed during the liveliness check.'
    )
    parser.add_argument('-d', '--domain', required=True, help='Target domain to enumerate')
    parser.add_argument('-o', '--output', required=True, help='Output file name')
    parser.add_argument('-f', '--format', required=True, choices=['1', '2'], help='Output format: 1 or 2')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode to log detailed information')
    parser.add_argument('--user-agent', default='Mozilla/5.0', help='Custom User-Agent string for requests')
    parser.add_argument('--live-check', action='store_true', help='Perform a liveliness check on found targets. Requires --port and --proxy options.')
    parser.add_argument('--proxy', help='Proxy to use for HTTP requests (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--port', type=str, help='Additional ports to check (comma-separated)', default='')

    args = parser.parse_args()
    additional_ports = list(map(int, args.port.split(','))) if args.port else []
    main(args.domain, args.output, args.format, args.debug, args.user_agent, args.live_check, args.proxy, additional_ports)