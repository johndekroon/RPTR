#-------------------------------------------------------------------------------
# Name:        RPTR rifle
# Purpose:     Fire the bullets
#
# Author:      John de Kroon
#
# Created:     25-05-2016
# Copyright:   (c) John de Kroon 2016
# Version:     1.0
#-------------------------------------------------------------------------------

import os
import subprocess
from dbmanager import *
import time

class Rifle:
    'shoots bullets'
    
    def __init__(self, id_test, command):
        #create new dbmanager
        self.dbmanager = Dbmanager()
        #fire bullet
        self.fire_bullet(id_test, command)
    
    def fire_bullet(self, id_test, command):            
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        #get current time
        start = time.time()
        #start tool execution in new proces
        p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        #get output form process
        out, err = p.communicate()
        #calculate how much time the tool used
        exec_time = time.strftime("%H:%M:%S", time.gmtime(time.time() - start))
        #write tool output to database
        self.dbmanager.tool_log_create(id_test, command, exec_time, out)