#!/usr/bin/python

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
import xfexchange

def getbyDate(date):
	furl = "https://isc.sans.edu/api/getmspatchday/%s?json" % date
	headers = {"Accept": "application/json",
		   'User-Agent': 'Mozilla 5.0'}
	request = urllib2.Request(furl, None, headers)
	data = urllib2.urlopen(request)
	data2 = json.loads(data.read())
	return data2

def pt_toWeb(date):
	returner = ""
	for item in getbyDate(date)["getmspatchday"]:
		returner += '''<ul> <b>%s</b>
		<li>Known Exploits: <b>%s</b></li>
		<li>Affects: %s</li>
		<li>Severity: %s </li>
		<li>Client / Server: %s</li>
		<li>Title: %s</li>
		<li></li></ul>
		''' % (item["id"], item["exploits"], item["affected"], item["severity"], 
		item["clients"] + " / " +item["servers"], item["title"], ) 
	return returner
	
	
parser = OptionParser()
parser.add_option("-d", "--date", dest="date" , default=None,
                  help="date of Patch Tuesday ", metavar="YYYY-MM-DD")


(options, args) = parser.parse_args()

if options.date is not None:
	for item in getbyDate(options.date)["getmspatchday"]:
		print item
