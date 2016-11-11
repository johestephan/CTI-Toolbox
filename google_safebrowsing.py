
#!/usr/bin/python

import urllib
import urllib2
import json
import hashlib
import os.path
import os
import sys

import iprep_conf as IC

def lookup(url):
    url = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=demo-app&key=%s&appver=1.5.2&pver=3.1&url=%s" % (IC.go_key, url)
    headers = {"User-Agent": "Mozilla 5.0"}
    request = urllib2.Request(url, None, headers)
    data = urllib2.urlopen(request)
    result = data.read()
    return {"Google_Safebrowsing" : result}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print '''google.py Version 1.0 (alpha) by J.S.
        usage: google.py URL\n
        '''
    else:
        print lookup(sys.argv[1])

    exit(0)