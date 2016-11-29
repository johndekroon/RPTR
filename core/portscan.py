#-------------------------------------------------------------------------------
# Name:        RPTR Portscan
# Purpose:     Portscanning
#
# Author:      John de Kroon
#
# Created:     03-10-2016
# Copyright:   John de Kroon (c)
# Version:     1.0
#-------------------------------------------------------------------------------

import os
import subprocess
import time
import urllib2
import difflib
import ssl

from lxml import etree
from dbmanager import *

class Portscan():
    def __init__(self, id_test, target, save_path):
        self.ports = []
        self.id_test = id_test
        self.target = target
        self.save_path = save_path
        self.output = None
        #fire bullet
        self.dbmanager = Dbmanager()
        #management interfaces
        self.manif = ['ssh', 'telnet', 'vnc', 'ftp', 'mysql', 'microsoft-ds', 'msrpc']
        self.manif_found = False

    def parse(self, file_name):
        port80 = False
        
        doc = etree.parse(file_name)
        for x in doc.xpath("//host[ports/port[state[@state='open']]]"):
            for open_p in x.xpath("ports/port[state[@state='open']]"):
                item = open_p.attrib.values()
                port = item[1]
                for child in list(open_p):
                    service = None
                    product = None
                    version = None
                    tunnel = None
                    for x in child.attrib.iteritems():
                        if(x[0] == 'name'):
                            service = x[1]
                        if(x[0] == 'product'):
                            product = x[1]
                        if(x[0] == 'version'):
                            version = x[1]
                        if(x[0] == 'tunnel'):
                            tunnel = x[1]
                #following test is added to prevent double scanning
                if port == "80":
                    port80 = True
                if port == "443" and port80:
                    if self.check_diff_80_443(self.target):
                        print "80 and 443 are same site"
                        self.ports.append({"port": port, "service": service, "product": product, "version": version, "tunnel": tunnel, "duplicate": True})
                        continue
                #check if management interface is detected
                if service in self.manif:
                    self.manif_found = True
                self.ports.append({"port": port, "service": service, "product": product, "version": version, "tunnel": tunnel, "duplicate": False})   

    def fire_scan(self):
        #get current time
        start = time.time()
        #start tool execution in new proces
        command = "nmap --open --top-ports=50 -sV -oX "+self.save_path+"/nmap_scan.xml "+self.target
        p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        #get output form process
        out, err = p.communicate()
        self.output = out
        #calculate how much time the tool used
        exec_time = time.strftime("%H:%M:%S", time.gmtime(time.time() - start))
        #write tool output to database
        id_tool_log = self.dbmanager.tool_log_create(self.id_test, command, exec_time, out)
        #parse result
        self.parse(self.save_path+"/nmap_scan.xml")
        #if management ports are open, create a vulnerability for it 
        if self.manif_found:
            self.dbmanager.vulnerability_create(self.id_test, id_tool_log, 1, out)
        
    def get_ports(self):
        return self.ports
        
    #check if port 80 and 443 are the same
    #used to prevent double scanning a website
    def check_diff_80_443(self, url):
        try:
            url = url.replace("'", "")
            f = urllib2.urlopen("http://"+url)
            html80 = f.read(25000).replace("http://", "https://")
        
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                f = urllib2.urlopen("https://"+url, context=ctx)
            except:
                f = urllib2.urlopen("https://"+url)
        
            html443 = f.read(25000)
	    
            s = difflib.SequenceMatcher(lambda x: x == " ", html443, html80)
            if round(s.ratio(), 3) > 0.75:
                return True
            return False
        except:
            return False