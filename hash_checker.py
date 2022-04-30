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

print(len(args.api))
print(len(args.hash))
if len(args.hash) != 16 and len(args.hash) != 32 and len(args.hash) != 64:
	print("Improper hash length. Please enter an md5 or sha256 hash value.")
	sys.exit()

session = requests.Session()
session.headers = {'Accept' : 'application/json', 'X-Apikey' : args.api}
url = f"https://www.virustotal.com/api/v3/search?query={args.hash}"
response = session.get(url)

rcode = int(re.search(r'\d+', str(response)).group())
print("API Response Code: " + str(rcode))
if rcode != 200:
	print("API call failed. Please check your API key or hash value.")
	sys.exit()
if "[]" in response.text:
	print("No results have been found for the specified hash.")
	sys.exit()

data = str(re.search(r'"last_analysis_stats":\s\{(.*?)\}',str(response.text),flags=re.S).group())
replace = '",{} '
for char in replace:
	data = data.replace(char,"")
data = ''.join(data.splitlines(keepends=True)[2:])
print("\nRaw data: \n" + data)

malicious=0
for entry in data.split("\n"):
	if "malicious" in entry:
		malicious = int(re.search(r'\d+', str(entry)).group())

print("Results:")
if malicious >= 5:
	print(f"This file has been detected by {malicious} AV engines and has been deemed a threat.")
elif malicious > 0 and malicious < 5:
	print(f"This file has been detected by {malicious} AV engines and could possibly be malicious.")
else:
	print("This file is clean.")