#!/usr/bin/python3
# Vaughn Woerpel
# VirusTotal Hash Checker
# Syntax: ./hash_checker.py {api} {hash}
from os import sys
import requests
import argparse
import re

print("\n---VirusTotal Hash Checker---")

# Setting up passing in arguments. Takes in the API key and the hash value. Both are required.
parser = argparse.ArgumentParser(description="Python tool to search VirusTotal using md5/sha256 hashes.",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("api", help="VirusTotal API Key.")
parser.add_argument("hash", help="Hash value to search for.")
args = parser.parse_args()

# Checks whether the hashes are valid. md5 can be either 16 or 32, and sha256 is 64. Quick and easy way to check.
if len(args.hash) != 16 and len(args.hash) != 32 and len(args.hash) != 64:
	print("Improper hash length. Please enter an md5 or sha256 hash value.")
	sys.exit()

# Handles sending the actual API call with requests. Sends header defining application search and our API key.
session = requests.Session()
session.headers = {'Accept' : 'application/json', 'X-Apikey' : args.api}
# Adds the hash value to the end of the URL to function as what we're using as the query
url = f"https://www.virustotal.com/api/v3/search?query={args.hash}"
response = session.get(url)

# Gets the response code from the response data with a quick regex search.
rcode = int(re.search(r'\d+', str(response)).group())
# Prints response code and depending on whether the code is 200 or not the script either terminates or continues.
print("API Response Code: " + str(rcode))
if rcode != 200:
	print("API call failed. Please check your API key or hash value.")
	sys.exit()
# Checks to see if there is actually any data returned in the response. If not, it means that VT didn't find anything for the specified hash.
if "[]" in response.text:
	print("No results have been found for the specified hash.")
	sys.exit()

# Searches the full data section to find the analysis stats, then formats them and replaces characters to be easily readable.
data = str(re.search(r'"last_analysis_stats":\s\{(.*?)\}',str(response.text),flags=re.S).group())
replace = '",{} '
for char in replace:
	data = data.replace(char,"")
data = ''.join(data.splitlines(keepends=True)[2:])
# Prints out the raw data just because it's good information to have.
print("\nRaw data: \n" + data)

# Finds how many engines deemed the file as malicious
malicious=0
for entry in data.split("\n"):
	if "malicious" in entry:
		malicious = int(re.search(r'\d+', str(entry)).group())

# Depending on the count of malicious, tells the user that the file is either malicious, may be malicious, or is safe.
print("Results:")
if malicious >= 5:
	print(f"This file has been detected by {malicious} AV engines and has been deemed a threat.")
elif malicious > 0 and malicious < 5:
	print(f"This file has been detected by {malicious} AV engines and could possibly be malicious.")
else:
	print("This file is clean.")