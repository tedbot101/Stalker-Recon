import argparse
import os
from tqdm import tqdm

def combine_wordlists(file_list, output_file):
    combined_words = set()  # Use a set to automatically handle duplicates

    for file_name in tqdm(file_list, desc="Processing files"):
        if os.path.isfile(file_name):
            with open(file_name, 'r') as file:
                words = file.read().splitlines()  # Read lines and remove newline characters
                combined_words.update(words)  # Add words to the set
        else:
            print(f"File not found: {file_name}")

    # Write the combined words to the output file
    with open(output_file, 'w') as output:
        for word in sorted(combined_words):  # Sort the words before writing
            output.write(word + '\n')

    print(f"Combined wordlist saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Combine multiple wordlists into one, removing duplicates.")
    parser.add_argument('files', nargs='+', help='List of wordlist files to combine')
    parser.add_argument('-o', '--output', default='combined_wordlist.txt', help='Output file name (default: combined_wordlist.txt)')

    args = parser.parse_args()
    combine_wordlists(args.files, args.output)

if __name__ == "__main__":
    main()
