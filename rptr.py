#-------------------------------------------------------------------------------
# Name:        RPTR
# Purpose:     Automate automation
#
# Author:      John de Kroon
#
# Created:     25-05-2016
# Copyright:   (c) John de Kroon 2016
# Version:     1.0
#-------------------------------------------------------------------------------

import argparse

import subprocess
import json
import time
import os
import threading
import md5
import shutil

from core.report import *
from core.clip import *
from core.hound import *
from core.rifle import *
from core.dbmanager import *
from core.mass import *
from core.portscan import *

import conf

parser = argparse.ArgumentParser(prog='rptr.py', formatter_class=argparse.RawDescriptionHelpFormatter, description="""RPTR automates your automation
RPTR aims to orchestrate and interpret your tooling.

Example: rptr.py 192.168.1.1""")
parser.add_argument('--json', help="Output result in JSON string", action="store_true")
parser.add_argument('--list-tests', help="Get a list of test performed on the target. Usage: --list-test test.nl")
parser.add_argument('-b', help="Bullet file from the bullet dir")
parser.add_argument('-r', help="Get a report from the database. Usage: -r 14, where 14 is the report id")
parser.add_argument('-l', help="List vulnerabilities from mass scan from the database. Usage: -l 14, where 14 is the mass scan report id")
parser.add_argument('URL', nargs='*', help='URL or IP address to scan')

args = parser.parse_args()

verbose = True
id_scan = 0
report = None
id_mass = None
loots = []
threads = []
save_path = None

#if b arg is present, use supplied bullet. 
if(args.b):
    bullet_file = args.b
#if not, use default procedure (port scanning and tools registerd to the service
else:
    bullet_file = None

if(args.json):
    verbose = False
    
dbmanager = Dbmanager()

def start_rptr(url):
    global bullet_file
    global dbmanager
    global id_scan
    global id_mass
    global save_path
    global report
    
    profile = bullet_file
    if profile == None:
        profile = "Default"
    
    id_scan = dbmanager.test_create(url, id_mass, profile)
    report = Report(id_scan)
    report.set_verbose(True)
    
    report.printer("Start scan #"+str(id_scan)+" on "+url+"...")
    report.printer("Created DB entry. Scan ID is "+str(id_scan))
    
    start = time.time()
    save_path = create_dir()
    print save_path
    
    if bullet_file == None:
        portscanner = Portscan(id_scan, url, save_path)
        portscanner.fire_scan()
        ports = portscanner.get_ports()
        print ports
        get_clip("general")
        for port in ports:
            #skip duplicate functions (like 80 and 443)
            if port['duplicate'] == False:
                get_clip(port['service'], port['port'])
            if port['tunnel'] == 'ssl' and port['service'] == "https":
                get_clip(port['tunnel'], port['port'])
    else:
        get_clip(bullet_file)
    report.print_results(loots)
    exec_time = time.strftime("%H:%M:%S", time.gmtime((time.time() - start)))
    shutil.rmtree(save_path)
    report.printer("done")
    dbmanager.test_update_time(id_scan, exec_time)
    
def get_clip(bullet_file, port=None):
    global save_path
    #init list for the output
    output = []
    #get new clip
    clip = Clip(bullet_file)
    #set params
    if port != None:
        clip.setPort(port)
    clip.setSavePath(save_path)
    
    #read bullet file
    #if the bullet file doesn't exist or is invalid, just skip it
    if clip.read_bullet(url) == False:
        return False
    #get commands to execute from clip
    #bullets contains list with tools to execute
    bullets = clip.get_bullets()
    #list with all active threads
    threads = []
    
    #loop through bullets (tools)
    for x in bullets:
        #start new thread to fire bullet
        t = threading.Thread(target=fire, args=(x,))
        #add new thread to the tread list, at this point, thread is not started yet
        threads.append({"bullet": x, "thread": t})
        #start the thread
        t.start()
    
    for t in threads:
        #new hound
        hound = Hound(id_scan)
        print "Waiting for: "+t['bullet']
        #wait for thread to finish
        t['thread'].join()
        #get results with hound
        bullet_result = hound.loot_get(t['bullet'])
        #add the results to list
        output.append(bullet_result)
    
    #save loot (clip converts bullet output to vulnerabilities)
    save_loot(clip.process_results(output))
    #get recursive files
    new_clips = clip.get_clips()
    for new_clip in new_clips:
        get_clip(new_clip)
    
def save_loot(loot):
    global loots
    loots.append(loot)

def fire(bullet):
    global id_scan
    return Rifle(id_scan, bullet)

#create_dir() creates a dir that is used to store tmp files for scanners
#after the scan is finished, RPTR will try to remove this folder.
def create_dir():
    #generate random name
    m = md5.new()
    m.update(os.urandom(1337))
    random_hash = str(m.hexdigest())
    random_folder = "/tmp/"+random_hash
    
    if not os.path.exists(random_folder):
        #create folder
        os.makedirs(random_folder)
        #return path of folder for later use
        return random_folder
    #Is this the real life or is this just fantasy?
    else:
        return create_dir()

def escapeshellarg(arg):
    return "\\'".join("'" + p + "'" for p in arg.split("'"))

if(args.r):
    report = Report(args.r)
    report.set_verbose(verbose)
    report.get_report()
elif args.l:
    mass = Mass()
    targets = mass.get_mass_report(args.l)
    for target in targets:
        print "Vulnerabilities for "+target+" ("+str(len(targets[target]))+")"
        print
        for vuln in targets[target]:
            print str(vuln['id'])+": "+str(vuln['tool'])
        print
if(args.list_tests):
    report = Report(args.r)
    print report.test_list_domain(args.list_tests)
elif args.URL is None:
    print "Please provide an URL. For help use rptr.py --help"
else:
    #start RPTR
    for url in args.URL:
        start_rptr(escapeshellarg(url))
