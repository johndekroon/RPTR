#pythonscript is required because RAPTR sometimes throws a "Segmentation Fault" error while running the NMAP dirbuster. This script is trying to run the NMAP http-enum plugin a pre-defined max amount of times. If the Segmentation Fault is thrown 10 times in  row, the NMAP plugin http-enum will not be executed

import sys
import subprocess as sub
import os

target = sys.argv[1]
plugins = sys.argv[2]
maxAmount = 10
while(maxAmount > 0):
	cmd = 'nmap --script http-enum --script-args=\'http-enum.fingerprintfile=' + plugins + '/nmap-http-enum/custom-fingerprints.lua\' ' + target
	
	output = os.popen(cmd).read()
	#p = sub.call(['nmap', "--script", "http-enum #--script-args=http-enum.fingerprintfile=[plugins]/../bullets/dirb/custom-fingerpri#nts.lua", target], stdout = sub.PIPE, stderr = sub.PIPE)
	#output, errors = p.communicate()
	
	#print output
	if len(output) > 70:
		print output
		break
	maxAmount = maxAmount-1
	
	