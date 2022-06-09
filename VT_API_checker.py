#!/usr/bin/python3
import vt, argparse, os, pandas
from defang import defang

#Written by JLMW, just because.
#https://github.com/JayLMDubyew

parser = argparse.ArgumentParser(description='Check VirusTotal for potential malicious activity based on list of hashes or URLs')
parser.add_argument('-s','--hashlist', help='Hash (MD5, SHA1, or SHA256) list file')
parser.add_argument('-u','--urllist', help='URL list file')
parser.add_argument('-o','--outputfile', help='output file name. Extensions will be automatically added upon output generation.', required=True)
parser.add_argument('-d','--defang', type = int, help='0 - no URL defanging |  1 = defang URLs. Default = 1',default=1)
parser.add_argument('-m','--mode', type = int, help='0 - CSV | 1 = XLSX | Default = 1 (XLSX)', default=1)


#parser.add_argument('-f','--fresh', help="0 - check VT for existing information (default) | 1 - perform a fresh scan against the URL(s) or File(s")
args = parser.parse_args()

key = 'YOUR_KEY_HERE'
client = vt.Client(key)
url_results = []
hash_results = []

## number of requests allowed is subject to limitations per VirusTotal's Terms of Service


def urlScan(urllist):
	try:
		urls = open(urllist,'r')
		for url in urls.readlines():
			#print(url)
			url_id = vt.url_id(url)
			urlobject = client.get_object("/urls/{}", url_id)
			#print(urlobject.last_analysis_stats)
			url_dict = urlobject.last_analysis_stats
			if(args.defang):
				url = defang(url, all_dots=True)
			url_dict["identifier"] = url
			url_results.append(url_dict)
	except:
		print("No readable URL list found.")

def hashScan(hashlist):
	try:
		hashes = open(hashlist,'r')
		for hash in hashes.readlines():
			#print(hash)
			hashobject = client.get_object("/files/{}", hash)
			#print(hashobject.last_analysis_stats)
			hash_dict = hashobject.last_analysis_stats
			hash_dict["identifier"] = hash
			hash_results.append(hash_dict)

	except:
		print("No readable hash list found.")


def writeOutput(outputfile):
	if hash_results:
		frameHash = pandas.DataFrame(hash_results)
		hashident = frameHash.pop("identifier")
		frameHash.insert(0, hashident.name, hashident)
	if url_results:
		frameURL = pandas.DataFrame(url_results)
		urlident = frameURL.pop("identifier")
		frameURL.insert(0, urlident.name, urlident)

	if args.mode:
		outputfile = outputfile + ".xlsx"
		writer = pandas.ExcelWriter(outputfile, engine='xlsxwriter')

		if hash_results:
			frameHash.to_excel(writer, sheet_name='File Hash Results')
			print("Hash-based results written.")

		if url_results:
			frameURL.to_excel(writer, sheet_name='URL Results')
			print("URL-based results written.")

		writer.save()
	else:
		outputfile_url = outputfile+"_URL.csv"
		outputfile_hash = outputfile+"_HASH.csv"
		if url_results:
			frameURL.to_csv(outputfile_url)
			print("Hash-based results written.")
		if hash_results:
			frameHash.to_csv(outputfile_hash)
			print("URL-based results written.")


urlScan(args.urllist)
hashScan(args.hashlist)
client.close()
writeOutput(args.outputfile)
