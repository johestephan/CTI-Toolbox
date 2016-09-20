import feedparser
import sqlite3
import datetime
import os
import re
import sys
sys.path.append("./")
import mybasics
import indifetch



rsslist = ["http://www.malware-traffic-analysis.net/blog-entries.rss",
            "http://malc0de.com/rss/"]

def get():
    updtime = datetime.datetime.utcnow()
    returner = ""
    giplist = set()
    for url in rsslist:
        text = ""
        feed = feedparser.parse(url)
        try:
            for item in feed["items"]:
                text += str(item)     
            returner += '''##
                # %s
                ## 
                %s
                '''% (url, indifetch.getXML(text, ox="yes")) 
        except:
            print "ups"
    
    return returner

