#-------------------------------------------------------------------------------
# Name:        RPTR mass
# Purpose:     Manage recurent scans (currently not in use)
#
# Author:      John de Kroon
#
# Created:     05-07-2016
# Copyright:   (c) John de Kroon 2016
# Version:     1.0
#-------------------------------------------------------------------------------

import os
import conf
from dbmanager import *

class Mass():
    def __init__(self, type = None):
        self.type = type
        if self.type not in ("day", "week", "month", None):
            print "! Mass profile is not supported. Use day, week or month"
            exit()
        self.dbmanager = Dbmanager()
        if self.type is not None:
            self.id_mass = self.dbmanager.mass_create_log(self.type)
        
    def get_targets(self):
        targets = self.dbmanager.mass_get_targets()
        return targets
    
    def get_id_mass(self):
        return self.id_mass
    
    def get_mass_report(self, id):
        dbresult = self.dbmanager.mass_get_report(id)
        
        targets = {}
        for record in dbresult:
            if record[0] not in targets:
                targets[record[0]] = []
            targets[record[0]].append({'id': record[1], 'proof': record[3], 'tool': record[4]})
        return targets
    
    def get_bullet_file(self):
        return conf.get_config('mass_bullet_'+self.type)
        