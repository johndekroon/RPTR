#-------------------------------------------------------------------------------
# Name:        RPTR dbmanager
# Purpose:     Communicate with db
#
# Author:      John de Kroon
#
# Created:     17-06-2016
# Copyright:   (c) John de Kroon 2016
# Version:     1.0
#-------------------------------------------------------------------------------

import MySQLdb
import conf

class Dbmanager:
    def __init__(self):
        db_user = conf.get_config('db_user')
        db_pass = conf.get_config('db_pass')
        db_name = conf.get_config('db_name')
        self.conn = MySQLdb.Connection("localhost",db_user,db_pass,db_name)
        
    def __exit__(self, exc_type, exc_value, traceback):
        self.conn.close()
    
    def test_create(self, name, id_mass, profile = None):
        # prepare a cursor object using cursor() method
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO `scan` (`target`, `id_mass`, `profile`)VALUES (%s, %s, %s);", (name, id_mass, profile))
        id = cursor.lastrowid
        cursor.close()
        #commit insert
        self.conn.commit()
        return id
    
    def test_get(self, id):
        # prepare a cursor object using cursor() method
        cursor = self.conn.cursor()
        cursor.execute("SELECT target, id_template, tool_log.id as id_tool_log, proof, tool FROM `scan` JOIN vulnerabilities ON scan.id = vulnerabilities.id_scan JOIN tool_log ON vulnerabilities.id_tool_log = tool_log.id WHERE scan.id = %s", [id])
        result = cursor.fetchall()
        cursor.close()
        return result
    
    def test_list_domain(self, domain):
        # prepare a cursor object using cursor() method
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM `scan` WHERE target LIKE  %s", ["%"+domain+"%"])
        result = cursor.fetchall()
        cursor.close()
        return result
    
    def test_update_time(self, id, time):
        # prepare a cursor object using cursor() method
        cursor = self.conn.cursor()
        cursor.execute("UPDATE `scan` SET  `exec_time` =  %s WHERE  `id` = %s;", (time, id))
        cursor.close()
        #commit insert
        self.conn.commit()
        return id
    
    def tool_log_create(self, id_scan, tool, exec_time, output):
        # prepare a cursor object using cursor() method
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO `rptr`.`tool_log` (`id_scan`, `tool`, `exec_time`, `output`) VALUES (%s, %s, %s, %s);", (id_scan, tool, exec_time, output))
        id = cursor.lastrowid
        cursor.close()
        #commit insert
        self.conn.commit()
        return id
    
    def vulnerability_create(self, id_scan, id_tool_log, id_template, proof = None):
        # prepare a cursor object using cursor() method
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO `rptr`.`vulnerabilities` (`id_scan`, `id_tool_log`, `id_template`, `proof`) VALUES (%s, %s, %s, %s);", (id_scan, id_tool_log, id_template, proof))
        id = cursor.lastrowid
        cursor.close()
        #commit insert
        self.conn.commit()
        return id
    
    def mass_get_targets(self):
        # prepare a cursor object using cursor() method
        cursor = self.conn.cursor()
        cursor.execute("SELECT * from targets")
        result = cursor.fetchall()
        cursor.close()
        return result
    
    def mass_create_log(self, type):
        # prepare a cursor object using cursor() method
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO `mass` (`type`) VALUES (%s);", (type))
        id = cursor.lastrowid
        cursor.close()
        #commit insert
        self.conn.commit()
        return id
    
    def mass_get_report(self, id):
        # prepare a cursor object using cursor() method
        cursor = self.conn.cursor()
        cursor.execute("SELECT target, id_template, tool_log.id as id_tool_log, proof, tool FROM `scan` JOIN vulnerabilities ON scan.id = vulnerabilities.id_scan JOIN tool_log ON vulnerabilities.id_tool_log = tool_log.id WHERE scan.id_mass = %s order by target", [id])
        result = cursor.fetchall()
        cursor.close()
        return result
    
    def hound_loot_get(self, id_test, bullet):
        # prepare a cursor object using cursor() method
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM  `tool_log` WHERE  `id_scan` = %s AND  `tool` = %s LIMIT 0 , 30", [id_test, bullet])
        result = cursor.fetchall()
        cursor.close()
        return result
        
