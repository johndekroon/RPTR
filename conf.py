# RPTR configuration file
import os

config = {}

config['default_template'] = "nl_template.xml"
config['bullets_dir'] = os.path.dirname(os.path.realpath(__file__))+"/bullets/"
config['plugins_dir'] = os.path.dirname(os.path.realpath(__file__))+"/plugins/"
config['templates_dir'] = os.path.dirname(os.path.realpath(__file__))+"/templates/"

#default bullets
#xml bullet file in the bullets dir, WITHOUT the .xml extension
config['default_bullet'] = ""
config['mass_bullet_day'] = ""
config['mass_bullet_week'] = ""
config['mass_bullet_month'] = ""

#db creds
config['db_user'] = ""
config['db_pass'] = ""
config['db_name'] = ""

def get_config(key):
    global config
    return config[key]