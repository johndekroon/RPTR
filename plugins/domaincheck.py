#!/usr/bin/env python
#
# whoischeck.py | (C) copyright 20016 | v2016.06.28
#
import subprocess
import sys
import re
import json
import urllib
import urllib2
import argparse
import socket

if len(sys.argv) != 2:
    print "USAGE: domaincheck.py <domain>"
    sys.exit(1)

domain  = sys.argv[1].lower()

# Minor sanity check on domain input since we're using 'shell=True' execute
if re.search("^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", domain) == None:
    print "ERROR: No valid domainname provided"
    sys.exit(1)

# Set default values
found   = False            # Holds WHOIS found status output:    True/False
dnssec  = "Unknown"        # Holds DNSSEC status output:         True/False/Unknown
status  = "Not applicable"    # Holds (EPP) Transfer-Status output:    True/False/Not applicable
apikey = "" # API key for virustotal

def parse_response_url(jsonResp, url):
    if int(jsonResp['positives']) > 0:
        print "Malware detected on URL "+url+" by "+str(jsonResp["positives"])+ " scanner(s):"
        for x in jsonResp['scans']:
            if jsonResp['scans'][x]['detected'] == True:
                print " - "+x
        ip_address = socket.gethostbyname(url)
        scan_ip(ip_address)
    else:
        print "Host is clean"

def parse_response_ip(jsonresp, ip):
    mal_results = ""
    found = False
    for x in jsonresp['detected_urls']:
        if x['positives'] > 0:
            mal_results = mal_results+">> "+x['url']+" ("+str(x['positives'])+")\n"
            found = True
    if found:
        print "Malware detected on IP "
        print mal_results
        
def scan_ip(ip):
    global apikey
    print "Start scan on IP "+ip
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    parameters = {'ip': ip, 'apikey': apikey}
    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
    jsonresp = json.loads(response)
    
    parse_response_ip(jsonresp, ip)
    
def scan_url(scanurl):
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    parameters = {'resource': scanurl, 'scan': 1, 'apikey': apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req).read()
    jsonResp = json.loads(str(response))
    parse_response_url(jsonResp, scanurl)

# Perform WHOIS
try:
    result = subprocess.Popen("pwhois -r " + domain, shell=True, stdout=subprocess.PIPE).stdout.read()
except:
    # pwhois will still throw Root WHOIS server for TLD not found exceptions to the STDOUT, cannot surpress it this way
    result = sys.exc_info()[0]

# Lowercase everything for easier string-matching later
resultIgnoreCase = result.lower()

# First check for errors, secondly for domainname not found and only finally try to parse the result
if ("traceback (most recent call last)" in resultIgnoreCase or "try again" in resultIgnoreCase or "exceeded" in resultIgnoreCase):
    print "ERROR: WHOIS exception occured; see raw details for more info."
    
elif (    "not found"             in resultIgnoreCase or 
    "status: available"         in resultIgnoreCase or 
    "no match for "         in resultIgnoreCase or 
    "no matching record"          in resultIgnoreCase or 
    "no whois information found."     in resultIgnoreCase or
    "we do not have an entry in "    in resultIgnoreCase or
    len(resultIgnoreCase) < len(domain)):
    print "ERROR: Domainname WHOIS not found; domain is probably not registered"
    
else:
    found = True
    # Most TLDs support DNSSEC; only a few exotic ones do not; we'll assume all TLDs support it for now.
    # More details can be found at: http://stats.research.icann.org/dns/tld_report/
    match = re.search("^dnssec.*", resultIgnoreCase, re.MULTILINE)
    if (match != None):
        match = match.group(0)
        if (    ("signed"     in match and not "unsigned" in match) or 
             "yes"        in match or 
             "true"       in match or 
             "active"     in match or 
             "locked"     in match or 
             "dnssec:y"     in match):
            dnssec = "True"
        else:
            dnssec = "False"

        # Check Domain-Transfer Status for TLDs supporting it.
        # See The EPP RFC 5731 for more info: http://tools.ietf.org/html/rfc5731
        # Currently we do not implement a full check; we only do a quick and dirty check for one or more types of 'prohibited' and ' locked' in all matches (can be multilined)
        status = "False"
        match = re.search("^domain status.*", resultIgnoreCase, re.MULTILINE)
        if (match == None):
            match = re.search("^status.*", resultIgnoreCase, re.MULTILINE)
            if (match == None):
                match = ""
            else:
                match = match.group(0)
        else:
            match = match.group(0)
    
        if "prohibited" in match:
            status = "True"
        else:
            status = "False" 
        
        scan_url(domain)
        

print "DOMAIN: " + domain
if found:
    print "DNSSEC ENABLED: " + dnssec
    print "TRANSFER STATUS LOCKED: " + status

print "RAW: " + result