import urllib
import urllib2
from optparse import OptionParser
import json
import hashlib
import os.path
import time
import re
import datetime
import sys


sys.path.append('./')
import iprep_conf as IC

#- general: General information about the IP, such as geo data, and a list of the other sections currently available for this IP address.
#- reputation: OTX data on malicious activity observed by AlienVault Labs (IP Reputation).
#- geo: A more verbose listing of geographic data (Country code, coordinates, etc.)
#- malware: Malware samples analyzed by AlienVault Labs which have been observed connecting to this IP address.
#- url_list: URLs analyzed by AlienVault Labs which point to or are somehow associated with this IP address.
#- passive_dns: passive dns information about hostnames/domains observed by AlienVault Labs 



headers = {"X-OTX-API-KEY": "%s" % IC.otx_authkey,
		   "Accept": "application/json",
		   'User-Agent': 'Mozilla 5.0'}

def IPmax(ip):
	return dict(REip(ip.strip()).items() 
	+ MALip(ip.strip()).items() 
	+ GEip(ip.strip()).items() 
	+ URLip(ip.strip()).items()
	+ PADip(ip.strip()).items())

def PADip(value):
	furl = "%s" % "https://otx.alienvault.com:443/api/v1/indicators/IPv4/%s/passive_dns" % value
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())

def GEip(value):
	furl = "%s" % "https://otx.alienvault.com:443/api/v1/indicators/IPv4/%s/general" % value
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())

def URLip(value):
	furl = "%s" % "https://otx.alienvault.com:443/api/v1/indicators/IPv4/%s/url_list" % value
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())

def URL(value):
	furl = "%s" % "https://otx.alienvault.com:443/api/v1/indicators/url/%s/general" % value
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())

def CVE(value):
	furl = "%s" % "https://otx.alienvault.com:443/api/v1/indicators/cve/%s/general" % value
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())

def REip(value):
	furl = "%s" % "https://otx.alienvault.com:443/api/v1/indicators/IPv4/%s/reputation" % value
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())

def MALip(value):
	furl = "%s" % "https://otx.alienvault.com:443/api/v1/indicators/IPv4/%s/malware" % value
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())
	

def Pulseday():
	furl = "%s" % "https://otx.alienvault.com:443/api/v1/pulses/activity"
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())

def PulseSub():
	furl = "%s" % "https://otx.alienvault.com:443/api/v1/pulses/subscribed?limit=30"
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())
	
def getIndicators(id):
	furl = "https://otx.alienvault.com:443/api/v1/pulses/%s/indicators" % id
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())

def getMalhash(hash):
	furl = "https://otx.alienvault.com:443/api/v1/indicators/file/%s/analysis" % hash
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	return json.loads(data.read())


def parsePulse(data):
	thisset = dict()
	for item in data["results"]:
		for key, value in item.items():
			if key == "id":
				thisset = dict(thisset.items() + getIndicators(value).items())
	return thisset
