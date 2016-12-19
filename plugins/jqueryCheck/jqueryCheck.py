#-------------------------------------------------------------------------------
# Name:        jqueryCheck
# Purpose:     Command Line jqueryCheck
#
# Author:      John de Kroon
#
# Created:     06-01-2016
# Copyright:   (c) John de Kroon 2016
#
#-------------------------------------------------------------------------------

import urllib2
import re
import argparse

latestJqueryV = [1, 12, 4]
latestJqueryV2 = [2, 2, 4]

def retrieveVersion(input):
	if "/*! jQuery v" in input:
		version = re.compile('\d+').findall(input[0:20])
		if len(version) == 3:
			return version
	elif "* jQuery JavaScript Library" in input:
			version = re.compile('\d+').findall(input[0:60])
			if len(version) == 3:
				return version
	return None

def compareVersion(input):
	if(input == None):
		return
	#check for jquery v3, no support yet
	if int(input[0]) == 1:
		if int(input[1]) < latestJqueryV[1]:
			print " ! Alert: latest jQuery version is 1."+str(latestJqueryV[1])+"."+str(latestJqueryV[2])+", site uses: 1."+str(input[1])+"."+str(input[2])
		if input[1] == latestJqueryV[1]:
			if input[2] < latestJqueryV[2]:
				print " ! Alert: latest jQuery version is 1."+str(latestJqueryV[1])+"."+str(latestJqueryV[2])+", site uses: 1."+str(input[1])+"."+str(input[2])
		return
	if int(input[0]) == 2:
		if input[1] < latestJqueryV2[1]:
			print " ! Alert: latest jQuery version is 2."+str(latestJqueryV2[1])+"."+str(latestJqueryV2[2])+", site uses: 2."+str(input[1])+"."+str(input[2])
		if input[1] == latestJqueryV2[1]:
			if input[2] < latestJqueryV2[2]:
				print " ! Alert: latest jQuery version is 2."+str(latestJqueryV2[1])+"."+str(latestJqueryV2[2])+", site uses: 2."+str(input[1])+"."+str(input[2])
		return

parser = argparse.ArgumentParser(prog='jqueryCheck.py', formatter_class=argparse.RawDescriptionHelpFormatter, description="jQueryCheck.py checks whether the target uses the latest jQuery or not.")
parser.add_argument('URL', help='URL to scan')
parser.add_argument('--ssl', action='store_true', default=False)
args = parser.parse_args()	
targetUrl = args.URL
ssl = args.ssl

try:
    if ssl:
    	response = urllib2.urlopen('https://'+targetUrl)
    else:
    	response = urllib2.urlopen('http://'+targetUrl)
    for line in response.readlines():
    	if ("jquery" in line) and ".js" in line:
    		#Y U NO USING REGEX?!
    		jqueryUrl = line.replace('"', "")
    		jqueryUrl = jqueryUrl.replace("'", "")
    		split = jqueryUrl.split('src=', 1)
    		jqueryUrl = split[1]
    		split = jqueryUrl.split('.js', 1)
    		jqueryUrl = split[0]+".js"
    		print jqueryUrl
    		if("http://" in jqueryUrl) or ("https://" in jqueryUrl):
    			jqueryUrl = jqueryUrl
    		if("//" in jqueryUrl[0:2]):
    			jqueryUrl = "http:"+jqueryUrl
    		else:
    			jqueryUrl = 'http://'+targetUrl+'/'+jqueryUrl
    		jqueryFile = urllib2.urlopen(jqueryUrl).read(60)
    		#print retrieveVersion(jqueryFile)
    		compareVersion(retrieveVersion(jqueryFile[0:20]))
except:
    print "File not available"