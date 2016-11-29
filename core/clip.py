#-------------------------------------------------------------------------------
# Name:        RPTR rifle
# Purpose:     Supplies the bullets
#
# Author:      John de Kroon
#
# Created:     31-05-2016
# Copyright:   (c) John de Kroon 2016
# Version:     1.0
#-------------------------------------------------------------------------------

import os
import xml.etree.ElementTree as ET
import conf
import re

class Clip():
    def __init__(self, bullet_file = None):
        #do something
        self.url = ""
        self.bullets = []
        self.clips = []
        self.bullets_xml = None
        self.port = None
        self.save_path = None
        self.bullets_dir = conf.get_config('bullets_dir')
        self.plugins_dir = conf.get_config('plugins_dir')
        if bullet_file == None:
            self.bullet_file = conf.get_config('default_bullet')+".xml"
        else:
            self.bullet_file = bullet_file+".xml"
    
    #read bullet file and extract bullets from it    
    def read_bullet(self, url):
        self.url = url
        #try to read the bullet with ElementTree
        try:
            self.bullets_xml = ET.parse(self.bullets_dir + self.bullet_file).getroot()
        #ElementTree can't read the file. The file is unreadable or the XML is corrupt
        except:
            print " ! Warning: the bullet "+self.bullet_file+" is invalid or not found"
            return False
        #loop through bullets and add it to the bullet list
        for bullet in self.bullets_xml:
            self.bullets.append(self.prepare_bullet(bullet.find('execute').text))
    
    #replace placeholders with actual data
    def prepare_bullet(self, bullet):
        bullet = bullet.replace('[target]', self.url)
        bullet = bullet.replace('[path]', self.bullets_dir)
        bullet = bullet.replace('[save_path]', self.save_path)
        bullet = bullet.replace('[plugins]', self.plugins_dir)
        if self.port != None:
            bullet = bullet.replace('[port]', self.port)
        return bullet
    
    def get_bullets(self):
        return self.bullets
    
    def get_clips(self):
        return self.clips
    
    def process_results(self, output):
        item_count = len(output)
        searchObj = None
        self.result_list_size = self.getResultListSize(self.bullets_xml)
        result_list = [None] * self.result_list_size
        
        for x in range(0, item_count):
            output_item = output[x]
            id_tool_log = output_item['id']
            output_item = output_item ['output']
            bullet = self.bullets_xml[x]
            
            loots = bullet.find('loots')
            
            for loot in loots:
                regex = loot.find('regex').text
                #print regex
                searchObj = re.search(regex, output_item)
                if searchObj:
                    new_clip = self.saveFind(loot, 'execute')
                    if new_clip is not None:
                        self.clips.append(new_clip)
                    results = loot.find('results')
                    try:
                        for result in results:
                            id = result.find('id').text
                            desc = self.saveFind(result, 'description')
                            result_list.append({'id': id, 'desc': desc, 'id_tool_log': id_tool_log, 'match': searchObj.group(0), 'prove': output})
                    except:
                        continue
        
        return self.group_results(result_list)
    
    def group_results(self, result_list):
        resultGroupList = [None] * self.result_list_size
        for result in result_list:
            if result == None:
                continue
            rid = int(result['id'])
            if resultGroupList[rid] == None:
                resultGroupList[rid] = {'prove': result['prove'], 'id_tool_log': result['id_tool_log'], 'match': result['match'], 'description': result['desc']}
            if result['desc'] == None:
		continue
	    else:
                resultGroupList[rid]['description'] = resultGroupList[rid]['description'] + result['desc']
                
        return resultGroupList
    
    def saveFind(self, haystack, needle):
        needleObj = haystack.find(needle)
        return self.saveText(needleObj)

    def saveText(self, obj):
        result = None
        if obj is not None:
            result = str(obj.text)
        return result
    
    #if someone knows a better way just send your pull request :)
    def getResultListSize(self, bullets):
        size = 0
        for bullet in bullets:
            loots = bullet.find('loots')
            try:
                for loot in loots:
                    results = loot.find('results')
                    for result in results:
                        id = result.find('id')
                        if id is not None:
                            id = int(id.text)
                            if id > size:
                                size = id
            except:
                continue
        return int(size)+1
    
    def getBulletFile(self):
        return self.bullet_file
    
    def setPort(self, port):
        self.port = port
        
    def setSavePath(self, save_path):
        self.save_path = save_path
