# Certificate Enumeration Script

## Overview

This script is designed for enumerating SSL/TLS certificates associated with a specified domain. It leverages various APIs to gather information about certificates, including subdomains and endpoints. The script is particularly useful for security researchers and penetration testers looking to identify potential attack surfaces.

## Features

- **Certificate Enumeration**: Queries multiple sources to retrieve SSL/TLS certificates.
- **Liveliness Check**: Optionally checks the availability of discovered endpoints.
- **Custom User-Agent**: Allows users to specify a custom User-Agent string for requests.
- **Proxy Support**: Supports HTTP proxies for requests.
- **Debug Mode**: Logs detailed information for troubleshooting.

## Installation

1. **Clone the repository**:
```bash
   git clone https://github.com/yourusername/certificate-enumeration-script.git
   cd certificate-enumeration-script
```

2. **Install dependencies**:
```bash
   pip install -r requirements.txt
```

Set up API keys: Update the API_KEYS dictionary in the script with your API keys for the services used.

## Usage
Run the script with the following command:
```bash
python script.py -d <target_domain> -o <output_file_name> -f <format> [options]
Options
-d, --domain: Target domain to enumerate (required).
-o, --output: Output file name (required).
-f, --format: Output format: 1 (detailed) or 2 (endpoints only) (required).
--debug: Enable debug mode to log detailed information.
--user-agent: Custom User-Agent string for requests (default: Mozilla/5.0).
--live-check: Perform a liveliness check on found targets.
--proxy: Proxy to use for HTTP requests (e.g., http://127.0.0.1:8080).
--port: Additional ports to check (comma-separated, e.g., 4000,2330).
```
##Example
To enumerate certificates for example.com, save the results in output.json, and perform a liveliness check on default ports:
```bash
python script.py -d example.com -o output.json -f 1 --live-check --user-agent "MyCustomUserAgent/1.0"
```
To specify additional ports:
```bash
python script.py -d example.com -o output.json -f 1 --live-check --port 4000,2330
```
## Output
The script generates a JSON file containing the results of the enumeration, including found certificates and their associated endpoints. If the liveliness check is performed, the results will also include the status of each endpoint.

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
Inspired by tools like Amass, this script aims to provide a straightforward approach to certificate enumeration.

