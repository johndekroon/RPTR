#-------------------------------------------------------------------------------
# Name:        RPTR Hound
# Purpose:     Hound is here to take my loot
#
# Author:      John de Kroon
#
# Created:     16-08-2016
# Copyright:   (c) John de Kroon 2016
# Version:     1.0
#-------------------------------------------------------------------------------

from dbmanager import *

class Hound():
    def __init__(self, id_test):
        self.id_test = id_test
        #fire bullet
        self.dbmanager = Dbmanager()
        
    def loot_get(self, bullet):
        #get loot from database
        loot = self.dbmanager.hound_loot_get(self.id_test, bullet)
        
        #there should be a database entry, but ya never know
        if len(loot) == 0:
            print "ERROR: result not found!"
            #exit, wicked stuff is happening, call a priest
            exit()
        
        #get only first item
        loot = loot[0]
        #assemble result and return it
        return {'id': loot[0], 'output': loot[5]}