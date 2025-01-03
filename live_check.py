import argparse
import asyncio
import httpx
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def check_liveliness(endpoint, ports, rate_limit, proxy, user_agent):
    results = []
    async with httpx.AsyncClient(proxies=proxy, headers={"User-Agent": user_agent}) as client:
        for port in ports:
            url = f"http://{endpoint}:{port}"
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    results.append({"url": url, "status": "live", "status_code": response.status_code})
                    logging.info(f"{url} is live with status code {response.status_code}")
                else:
                    results.append({"url": url, "status": f"status code {response.status_code}", "status_code": response.status_code})
                    logging.warning(f"{url} returned status code {response.status_code}")
            except httpx.RequestError as exc:
                results.append({"url": url, "status": f"could not be reached: {exc}", "status_code": None})
                logging.error(f"{url} could not be reached: {exc}")
            await asyncio.sleep(1 / rate_limit)
    return results

async def main():
    parser = argparse.ArgumentParser(description="Perform liveliness check on endpoints from a file")
    parser.add_argument('--file', type=str, required=True, help='File containing endpoints to check')
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

    logging.info("Starting liveliness checks...\n")
    
    with open(args.file, 'r') as f:
        endpoints = {line.strip() for line in f if line.strip()}

    tasks = [check_liveliness(endpoint, args.ports, args.rate_limit, args.proxy, args.user_agent) for endpoint in endpoints]
    
    results = await asyncio.gather(*tasks)
    
    # Flatten the list of results
    flat_results = [item for sublist in results for item in sublist]
    
    # Filter out unreachable hosts unless --debug is specified
    if not args.debug:
        flat_results = [result for result in flat_results if 'could not be reached' not in result['status']]
    
    # Save the liveliness check results to a JSON file
    with open('liveliness_check_results.json', 'w') as f:
        json.dump(flat_results, f, indent=4)
    
    logging.info("Liveliness check results have been saved to liveliness_check_results.json")

if __name__ == "__main__":
    asyncio.run(main())