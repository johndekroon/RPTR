#-------------------------------------------------------------------------------
# Name:        RPTR reporter
# Purpose:     Report findings
#
# Author:      John de Kroon
#
# Created:     25-05-2016
# Copyright:   (c) John de Kroon 2016
# Version:     1.0
#-------------------------------------------------------------------------------

import xml.etree.ElementTree as ET
import conf
import json
from dbmanager import *

class Report:
    def __init__(self, id_test = None):
        #do something
        self.dbmanager = Dbmanager()
        self.id_test = id_test
        self.verbose = True
        
    def test_list_domain(self, domain):
        list = self.dbmanager.test_list_domain(domain)
        return list
    
    def print_results(self, loots):
        results = self.merge_lists(loots)
        for result in results:
            self.dbmanager.vulnerability_create(self.id_test, result['id_tool_log'], result['id'], result['match'])
        self.get_report(self.id_test)
    
    def merge_lists(self, loots):
        results = []
        for loot_list in loots:
            for x in range(0, len(loot_list)):
                if loot_list[x] is not None:
                    loot_list[x]['id'] = x
                    results.append(loot_list[x])
        return results
    
    def prepare_verbose(self, results):
        templates_dir = conf.get_config('templates_dir')
        template_name = conf.get_config('default_template')
        template_xml = ET.parse(templates_dir + template_name).getroot()
        print "RPTR found "+str(len(results))+" findings"
        print
        for result in results:
            x = str(result['id'])
            xmlresults = template_xml.findall(".//title/..[id='"+x+"']")
            if len(xmlresults) is not 0:
                print " >> "+xmlresults[0].find('title').text
                print "Description: "+xmlresults[0].find('description').text
                if result['description'] is not None:
                    print str(result['description'])
                print "Recommendation: "+xmlresults[0].find('recommendation').text
                print
            else:
                print " !! Unkown vulnerability found"
                print "ID: "+str(result['id'])
                print "Tool: "+result['prove']
                print "Please consider making a template for this vulnerability. Otherwise I *might* post on your Facebook that you like Justin Bieber"
                print
    
    def get_report(self, id_test = None):
        result = self.dbmanager.test_get(self.id_test)
        result_dict = {}
        try:
            if result[0][0] is None:
                print "Report not found or no findings"
                return None
            result_dict['target'] = result[0][0]
        except:
            print "Not found"
            return None
        if self.verbose is True:
            self.get_report_verbose(result)
        else:
            self.parseResultsJson(result)
    
    def get_report_verbose(self, result):
        print "Results for target: "+result[0][0]
        result_list = []
        for row in result:
            result_list.append({'id': str(row[1]), 'prove': row[4], 'id_tool_log': row[2], 'match': row[3], 'description': None})
        self.prepare_verbose(result_list)

    def addJsonString(self, jsonString):
        global resultList
        try:
            jsonIter = json.loads(jsonString)
            for item in jsonIter:
                resultList.append(item)
        except:
            #sorry...
            print "kapot"
            pass
    
    def parseResultsJson(self, result):
        result_list = []
        for row in result:
            result_list.append({'id': str(row[1]), 'prove': row[4], 'id_tool_log': row[2], 'match': row[3], 'description': None})
        print json.dumps(result_list)
    
    def saveFind(self, haystack, needle):
        needleObj = haystack.find(needle)
        return saveText(needleObj)
    
    def saveText(self, obj):
        result = None
        if obj is not None:
            result = str(obj.text)
        return result
    
    def printer(self, text):
        if self.get_verbose():
            print text
        else:
            print "sssh"
            
    def set_verbose(self, verbose):
        self.verbose = verbose
        
    def get_verbose(self):
        return self.verbose;