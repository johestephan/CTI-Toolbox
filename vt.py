import json
import urllib
import urllib2
import os.path
import sys

sys.path.append("./")
import iprep_conf

def getresult(key):
    parameters = { "ip" : key,
               "apikey": iprep_conf.vt_key}
    print parameters
    try:
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url,data)
        response = urllib2.urlopen(req)
        stre = response.read()
        print stre
        return json.loads(stre)
    except urllib2.HTTPError, e:
        print str(e)
    except:
        return ""


def urlresult(key):
    parameters = { "resource" : key,
               "apikey": iprep_conf.vt_key}
    try:
        data = urllib.urlencode(parameters)
        req = urllib2.Request(urlsearch,data)
        response = urllib2.urlopen(req)
        stre = response.read()
        return json.loads(stre)
    except:
        return ""
    
def search(text):
    parameters = { "ip" : text,
               "apikey": iprep_conf.vt_key }
    print parameters
    try:
        data = (urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read())
     
        return json.loads(data)
        
    except:
        return ""
        print "error"

url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
urlsearch = 'https://www.virustotal.com/vtapi/v2/url/report'
HOMEfolder = os.path.dirname(os.path.realpath(__file__))

