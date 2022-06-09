# VirusTotalChecker


usage: VT_API_checker.py [-h] [-s HASHLIST] [-u URLLIST] -o OUTPUTFILE [-d DEFANG] [-m MODE]

Check VirusTotal for potential malicious activity based on list of hashes or URLs

options:

  -h, --help            show this help message and exit

  
  -s HASHLIST, --hashlist HASHLIST
                        Hash (MD5, SHA1, or SHA256) list file
                        

  -u URLLIST, --urllist URLLIST
                        URL list file
                        

  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        output file name. Extensions will be automatically added upon output generation.

                        
  -d DEFANG, --defang DEFANG
                        0 - no URL defanging | 1 = defang URLs. Default = 1

                        
  -m MODE, --mode MODE  0 - CSV | 1 = XLSX | Default = 1 (XLSX)
