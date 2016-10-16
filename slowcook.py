import urllib2
import urllib
import json
import sys
from datetime import datetime, timedelta

sys.path.append("./")
import iprep_conf as IC

yesterday = datetime.now() - timedelta(days=5)
YEST = yesterday.strftime('20%y-%m-%dT00:00:00Z')

headers = {"Authorization": "Basic %s " % IC.xfex_cred,
           "Accept": "application/json",
           'User-Agent': 'Mozilla 5.0'}

URLBase = "https://api.xforce.ibmcloud.com"
URLd1 = {"IP": "/ipr/",
    "MALWARE": "/ipr/malware/",
    "INTR": "/ipr?category=%s&startDate=%s&limit=%s"}

INTRcat  = { "1" : "Spam",
            "2" : "Anonymisation Services",
            "3" : "Scanning IPs",
            "4" : "Dynamic IPs",
            "5" : "Malware",
            "6" : "Bots",
            "7" : "Botnet Command and Control Server"}

def ask(url):
    try:
        request = urllib2.Request(url, None, headers)
        data = urllib2.urlopen(request)
        data2 = json.loads(data.read())
        return data2
    except:
        return { url : "Error in Connection"}

def pgInsert(string):
    return ""

def searchHIGHroller(iplist):
    #try:
        retdata = ""
        for count in range(1,len(INTRcat)+1):
            mydata = dict(slowcookINTRIP(str(count)))
            for Sitem in mydata["rows"]:
                if str(Sitem["ip"]) in iplist:
                    retdata += '''%s; %s; %s; %s\n''' % (INTRcat[str(count)], Sitem["ip"], Sitem["score"], Sitem["created"])
        return retdata

def getHIGHroller(limit=8.0):
    today = datetime.now()
    HR_jdata = dict()
    HR_jdata.update({"today" : today})
    for count in range(1,len(INTRcat)+1):
        mydata = dict(slowcookINTRIP(str(count)))
        new_jdata = []
        for Sitem in mydata["rows"]:
            if "score" in str(Sitem):
                if Sitem["score"] > limit:
                    temp_jdata = [Sitem["ip"], Sitem["score"], Sitem["created"]]
                    new_jdata.append(temp_jdata)
                   
        ret_jdata = {INTRcat[str(count)]:new_jdata }
        HR_jdata.update(ret_jdata)
    
    HR_jdata.update
    return HR_jdata     

    
    
def slowcookINTRIP(cat="1"):
    try:
        dataset = {}
        url = URLBase + (URLd1["INTR"] % (urllib.quote_plus(INTRcat[cat]), YEST, 2000))
        return ask(url)
    except:
        return "Error in function (getBIG)"
        
    
def getIP(ip):
    try:
        url = URLBase + URLd1["IP"] + ip.strip()
        return ask(url)
    except:
        return "Error in function (getIP)"