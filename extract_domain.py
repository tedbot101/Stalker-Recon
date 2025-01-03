import tldextract

def extract_domains(input_file, output_file):
    with open(input_file, 'r') as file:
        subdomains = file.readlines()
    
    domains = set()
    for subdomain in subdomains:
        subdomain = subdomain.strip()
        extracted = tldextract.extract(subdomain)
        domain = f"{extracted.domain}.{extracted.suffix}"
        domains.add(domain)
    
    with open(output_file, 'w') as file:
        for domain in sorted(domains):
            file.write(domain + '\n')

if __name__ == "__main__":
    input_file = 'subdomains.txt'  # Replace with your input file name
    output_file = 'domains.txt'    # Replace with your desired output file name
    extract_domains(input_file, output_file)