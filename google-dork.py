import sys
import json
from googlesearch import search
from tqdm import tqdm

def google_search(query, num_results=10):
    results = []
    for result in search(query, num_results=num_results):
        results.append(result)
    return results

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Google Dorking Script")
    parser.add_argument("target", help="Target domain")
    parser.add_argument("-e", "--export", action="store_true", help="Export results to a JSON file")
    parser.add_argument("-f", "--filename", type=str, default="results.json", help="Filename for the exported JSON file")
    args = parser.parse_args()

    target = args.target
    queries = [
        f'site:*<{target}',
        f'site:*<-{target}',
        f'site:*>*{target}',
        f'site:*->{target}',
        f'site:*<->{target}',
        f'site:*<{target} intext:"login" | intitle:"login" | inurl:"login" | intext:"username" | intitle:"username" | inurl:"username" | intext:"password" | intitle:"password" | inurl:"password"'
    ]

    all_results = {}
    for query in tqdm(queries, desc="Processing queries"):
        results = google_search(query)
        if not results:
            all_results[query] = "No results found"
        else:
            all_results[query] = results

    if args.export:
        with open(args.filename, 'w') as f:
            json.dump(all_results, f, indent=4)
        print(f"\nResults exported to {args.filename}")
    else:
        print(json.dumps(all_results, indent=4))
