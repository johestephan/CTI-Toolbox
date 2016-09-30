import os
import sys
import re
from __builtin__ import next
import datetime

sys.path.append("./")
import redactit_zone
    
def redactIP(ip):
    iplist = ip.split(".")
    newip = ".".join(iplist[0:3])+"[.]"+iplist[3]
    return newip

def redactemail(email):
    itemlist = email.split("@")
    domain = itemlist[1].split(".")
    newdomain = ".".join(domain[0:len(domain)-1])+"[.]"+ str(domain[-1])
    newemail = itemlist[0]+"[@]"+ str(newdomain)
    return newemail


def redactit(text, searchkey=None):
    ip = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
    
    redactDictBASIC = {"http" : "hxxp", "meow" : "hxxp","HTTP" : "hxxp"}
	    
    redactDict = {}
    searchkeyDict = {}
    if searchkey is not None:
        if len(searchkey) > 1:
            Redact_String = "<REDACTED>"
            for item in searchkey.split(","):
                if (item.startswith("$#=")):
                    Redact_String = item.split("=")[1]
                else:   
                    searchkeyDict.update({item.strip(): Redact_String})
            for key, value in searchkeyDict.items():
                text = text.replace(str(key).strip(), str(value).strip())
            
    for item in ip.findall(text):
        redactDict.update({item: redactIP(item)})

    email = re.compile(r'[\w\.-]+@[\w\.-]+')
    for item in email.findall(text):
        redactDict.update({item: redactemail(item)})
    for key, value in redactDict.items():
        text = text.replace(str(key).strip(), str(value).strip())
    for key, value in redactDictBASIC.items():
        text = text.replace(str(key).strip(), str(value).strip())
    for key, value in redactit_zone.ROOOT_Domain_List.items():
        text = text.replace(str(key).strip(), str(value).strip())      
    return text
    

