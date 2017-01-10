import sys
import urllib2
from optparse import OptionParser
import json
sys.path.append("./")
import iprep_conf as _IC

INIT_MISPurl = "http:192.168.56.50"
INIT_MISPauthkey = ""
INIT_XFEauthkey = _IC.xfex_cred
INIT_XFEcollid = ""



parser = OptionParser()
parser.add_option("-m", "--misp", dest="MISPURL" , default=INIT_MISPurl,
                  help="Url of MISP instance ", metavar="http://ADDRESS:8080")
parser.add_option("-c", "--coll", dest="COLLECTIONid" , default=None,
                  help="ID of the XForce collection", metavar="CollectionID")

(options, args) = parser.parse_args()

MISP_baseurl = str(options.MISPURL)+"attribute/text/download/"
my_indicators = ["md5", "filename", "ip-src"]

XFE_headers = {"Authorization": "Basic %s " % INIT_XFEauthkey,
		   "Accept": "application/json",
		   'User-Agent': 'Mozilla 5.0'}

def moveall():
	for my_urlextension in my_indicators:
		request = urllib2.Request(MISP_baseurl+my_urlextension)
		data = urllib2.urlopen(request)
		Create_Stix_for(my_urlextension)
		for line in data.read():
					

