#!/usr/bin/python

import urllib
import urllib2
from optparse import OptionParser
import json
import hashlib
import os.path
import time
import re
from datetime import datetime, timedelta

import sys

sys.path.append('./')
import iprep_conf as IC

yesterday = datetime.now() - timedelta(days=1)
YEST = yesterday.strftime('20%y-%m-%dT00:00:00Z')


headers = {"Authorization": "Basic %s " % IC.xfex_cred,
		   "Accept": "application/json",
		   'User-Agent': 'Mozilla 5.0'}

def getPAM(text):
	furl = "https://api.xforce.ibmcloud.com/signatures/fulltext?q=%s" % text.strip()
	
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	data2 = json.loads(data.read())
	return data2["rows"][0]["pamid"].strip()

def getXFD_fromCVE(cve):
	furl = "https://api.xforce.ibmcloud.com/vulnerabilities/search/%s" % cve.strip()
	
	request = urllib2.Request(furl, None, headers)
	try:
		data = urllib2.urlopen(request)
		data2 = json.loads(data.read())
		return data2[0]["xfdbid"]
	except:
		return "Not found"

def getXFD(pamid):
	furl = "https://api.xforce.ibmcloud.com/signatures/%s" % pamid
	
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	data2 = json.loads(data.read())
	return data2["protects_against"]["xfdbid"]

def getFull(xfid):
	if xfid == "Not found":
		return xfid
	furl = "https://api.xforce.ibmcloud.com/vulnerabilities/%s" % xfid
	
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	data2 = json.loads(data.read())
	list = []
	return [data2[u"description"], data2[u"risk_level"], data2[u"platforms_affected"], data2[u"stdcode"]]


def POSTcaseBody(cid, data):
	furl = "https://api.xforce.ibmcloud.com/casefiles/%s/attachments" % cid

        request = urllib2.Request(furl, data, headers)
        data = urllib2.urlopen(request)
        data2 = json.loads(data.read())
	return data


def getip(ip):
	try:
		furl = "https://api.xforce.ibmcloud.com/ipr/%s" % ip
		furl2 = "https://api.xforce.ibmcloud.com/ipr/malware/%s" % ip
	
		request = urllib2.Request(furl, None, headers)
		data = urllib2.urlopen(request)
		data2 = json.loads(data.read())
		request = urllib2.Request(furl2, None, headers)
                data = urllib2.urlopen(request)
                data3 = json.loads(data.read())
		merged_dict = {key: value for (key, value) in (data2.items() + data3.items())}
		return merged_dict
		#return str(data2)
		#return [data2[u"history"][0]["geo"]["country"], data2[u"score"], data2[u"reason"], data2[u"categoryDescriptions"]]
	except:
		return [str(data2), "Ups", "Ups", "ups"]

def ixf_IPtoWeb(ip):
	dataset = getip(ip)
	return '''<ul><b> %s </b>
	<li>Description: %s</li>
	<li>Score: %s</li>
	<li>Geo Location: %s</li></ul>''' % (ip, str(dataset[3]), str(dataset[1]), str(dataset[0]))  

def ixf_m(text):
	return 0

def ixf_cve_forWeb(cve):
	result = getFull(getXFD_fromCVE(cve))
        print result
	return '''<ul><b> %s </b>
	<li>Description: %s</li>
	<li>Risk_level: %s</li>
	<li>Affected: %s</li>
	<li>STDcode: %s</li></ul>''' % (cve, result[0], result[1] , str(", ".join(result[2])),str(", ".join(result[3]))  )

def ixf_s(text):
	return getFull(getXFD(getPAM(text)))
	
def ixf_forWeb(text):
	result = ixf_s(text.strip(","))
	return '''<ul><b> %s </b>
	<li>Description: %s</li>
	<li>Risk_level: %s</li>
	<li>Affected: %s</li>
	<li>STDcode: %s</li></ul>''' % (text, result[0], result[1] , str(", ".join(result[2])),str(", ".join(result[3]))  )

def getColl():
	furl = "https://api.xforce.ibmcloud.com/casefiles/public" 

	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	data2 = json.loads(data.read())
	return data2
	#return (data2["casefiles"]["caseFileID"], data2["casefiles"]["title"], data2["casefiles"])

def getxfid_fromMS(msid):
	furl = "https://api.xforce.ibmcloud.com/vulnerabilities/msid/%s" % msid

	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	data2 = json.loads(data.read())	
	return data2

def getmsid(msid):
	furl = "https://api.xforce.ibmcloud.com/vulnerabilities/msid/%s" % msid

	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	data2 = json.loads(data.read())
	return data2

def getMalw(hash):
	furl = "https://api.xforce.ibmcloud.com/malware/%s" % hash

	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	data2 = json.loads(data.read())
	return data2


def getIP(id):
	furl = "https://api.xforce.ibmcloud.com/casefiles/%s/attachments" % id

	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	data2 = json.loads(data.read())
	iplist = set()
	for item in data2["attachments"]:
		if "IP" in item["report"]["type"]:
			iplist.add(item["report"]["title"])
	return iplist
	
#- Spam
#- Anonymisation Services
#- Scanning IPs
#- Dynamic IPs
#- Malware
#- Bots
#- Botnet Command and Control Server

def intrIPs(cat=None):
	dcata = { "1" : "Spam",
			"2" : "Anonymisation Services",
			"3" : "Scanning IPs",
			"4" : "Dynamic IPs",
			"5" : "Malware",
			"6" : "Bots",
			"7" : "Botnet Command and Control Server"}
	if cat is None:
		cata = dcata["7"]
		size = 45
	else:
		cata = dcata[cat]
		size = 45
	datar = dict() 
	
	furl = "https://api.xforce.ibmcloud.com/ipr?category=%s&startDate=%s&limit=%s" % (urllib.quote_plus(cata), YEST, size)
	request = urllib2.Request(furl, None, headers)
	try:
		data = urllib2.urlopen(request)
		data2 = json.loads(data.read())	
		datar1 = dict(datar.items() + data2.items())
		datar = datar1
	except:
		datar = "Error conecting API"
	return datar
	
	
def extractIP(text):
	ip = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
	return ip.findall(text)[0]
	
parser = OptionParser()
parser.add_option("-c", "--coll", dest="coll" , default=None,
                  help="Get a file of Public Collection IPS", metavar="filename")
parser.add_option("-i", "--ip", dest="ip" , default=None,
                  help="get IP intel", metavar="IP_Address")
parser.add_option("-s", "--sstr", dest="s_string" , default=None,
                  help="Get a file of Public Collection IPS", metavar="filename")
parser.add_option("-m", "--multiple", dest="s_PAMFILE" , default=None,
                  help="file of signature list, one PAM_Name per line", metavar="filename")
parser.add_option("-p", "--pam", dest="s_PAMSTRING" , default=None,
                  help="PAM string to be checked", metavar="single PAM_Name")


(options, args) = parser.parse_args()


HOMEfolder = os.path.dirname(os.path.realpath(__file__))

url = "https://api.xforce.ibmcloud.com"

if( options.s_string is not None ):
	result = ixf_s(options.s_string.strip(","))
	print "PAM_Name: %s\nDescription: %s\nRisk_level: %s \n\nAffected: %s\n\nSTDcode: %s\n" % (options.s_string.strip(","), result[0], result[1] , 
																							str(", ".join(result[2])), str(",".join(result[3])))
elif options.coll is not None:
	outfile = open(options.coll,"wb")
	outfile.write("## "+str(datetime.datetime.utcnow())+"\n")
	outfile.write(getColl())
	outfile.close()
	print "XForce Public Collections IP list updated and saved as %s" %  options.coll 
elif options.ip is not None:
	print getip(options.ip)
elif ( options.s_PAMFILE is not None ):
	fili = open(options.s_filename, "rb")
	ofili = open(options.s_filename+"_OUT", "wb")
	ofili.writelines("PAM_Name, Description, Risk_Score, Affected_Systems, STDcode")
	for line in fili.readlines():
		print line.strip(",")
		result = ixf_s(line.strip(","))
		ofili.writelines("%s,%s,%s,%s,%s" % (line.strip(","), result[0].replace(",", " "), result[1] , str(";".join(result[2])), str("; ".join(result[3]))))
		time.sleep(5)
elif( options.s_PAMSTRING is not None ):
	result = ixf_s(options.s_string.strip(","))
	print "PAM_Name: %s\nDescription: %s\nRisk_level: %s \n\nAffected: %s\n\nSTDcode: %s\n" % (options.s_string.strip(","), result[0], result[1] , 																						str(", ".join(result[2])), str(",".join(result[3])))
elif ( options.s_PAMFILE is not None ):
	fili = open(options.s_filename, "rb")
	ofili = open(options.s_filename+"_OUT", "wb")
	ofili.writelines("PAM_Name, Description, Risk_Score, Affected_Systems, STDcode")
	for line in fili.readlines():
		print line.strip(",")
		result = ixf_s(line.strip(","))
		ofili.writelines("%s,%s,%s,%s,%s" % (line.strip(","), result[0].replace(",", " "), result[1] , str(";".join(result[2])), str("; ".join(result[3]))))
		time.sleep(5)
