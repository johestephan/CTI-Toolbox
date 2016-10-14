import os
import sys
import re
import ipaddr
import urllib2
import datetime
sys.path.append("./")
import mybasics


INet = ["127.0.0.0/8","10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]

BOGUS = ["127.0.0.0/8","10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12","0.0.0.0/8", "100.64.0.0/10","169.254.0.0/16",
        "192.0.0.0/24","192.0.2.0/24","198.18.0.0/15", "198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","240.0.0.0/4"]

def getIP(text):
    IPlist = set()
    ip = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
    for item in ip.findall(text):
       IPlist.add(item)
    return IPlist
        
def getMD5(text):
    thisset = set()
    md5_r = re.compile(r"([a-fA-F\d]{32})")
    for item in md5_r.findall(text):
       thisset.add(item)
    return thisset

def getSHA256(text):
    thisset = set()
    sha_r = re.compile(r"([a-fA-F\d]{40})")
    for item in sha_r.findall(text):
       thisset.add(item)
    return thisset

def getCVE(text):
    CVElist = set()
    cve = re.compile("CVE[^\w]*\d{4}[^\w]+\d{4,}")
    for item in cve.findall(text):
        CVElist.add(item)
    return CVElist



def getXML(text, ox=None):
        backset = set()
        for item in getIP(text):
            backset.add(mybasics.StoXML("ip", item))
        for item in getCVE(text):
            backset.add(mybasics.StoXML("cve",item))
        for item in getMD5(text):
            backset.add(mybasics.StoXML("MD5", item))
        for item in getSHA256(text):
            backset.add(mybasics.StoXML("SHA256",item))
                
        if ox :
            return  " ".join(backset)
        else:
            return "%s" % "".join(backset)
        
def va(text, method=None):
    threatintel = str("".join(getCVE(text)))
    ipintel = str(getIP(text))
    print method
    if method.strip() == "ibm":
        print "uoihoijo"
        
        
    return '''<h1> Security/Threat Intelligence Report</h1>

        <h2> Threat/Event Intelligence</h2>
        %s
        <h2> IP Intelligence</h2>
        %s
        <h2> Raw Event data</h2>
        <table width = 440 align = center><tr><td>
        %s</td></tr></table>
        '''% (threatintel, ipintel, text)
        

    
