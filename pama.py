import urllib
import urllib2
import sys
import re

sys.path.append("./")
import redactit

headers = { 'User-Agent': 'Mozilla 5.0'}

def doAnalyse(text, key):
	IPlist = set()
	thisresponse = ""
	ip = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
	for item in ip.findall(text):
		IPlist.add(item)
    
	for myip in IPlist:
		url = "https://www.packetmail.net/iprep.php/%s?apikey=%s" % (myip, key)
		request = urllib2.Request(url, None, headers)
		data = urllib2.urlopen(request)
		thisresponse += str(data.read()) + "\n\n"
	return redactit.redactit(thisresponse)
			
			
	
