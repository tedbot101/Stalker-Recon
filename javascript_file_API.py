import requests
import re

def scrape_api_endpoints(js_url):
    try:
        # Fetch the JavaScript file
        response = requests.get(js_url)
        response.raise_for_status()  # Raise an error for bad responses

        # Use regex to find API endpoints (this is a basic example)
        # Adjust the regex pattern based on the expected format of the API URLs
        api_pattern = r'https?://[^\s)"]+'  # Matches URLs
        api_endpoints = re.findall(api_pattern, response.text)

        return api_endpoints

    except requests.exceptions.RequestException as e:
        print(f"Error fetching the JavaScript file: {e}")
        return []

# Example usage
js_file_url = 'https://example.com/path/to/javascript.js'  # Replace with the actual URL
api_endpoints = scrape_api_endpoints(js_file_url)

print("Found API Endpoints:")
for endpoint in api_endpoints:
    print(endpoint)
