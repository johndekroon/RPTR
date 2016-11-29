local io = require "io"
local string = require "string"
local table = require "table"

---HTTP Fingerprint files, compiled by Ron Bowes with a special thanks to...
-- o Kevin Johnson (@secureideas) for the fingerprints that come with Yokoso
--   http://yokoso.inguardians.com
-- o Jason H. (@jhaddix) for helping out with a whole pile of fingerprints he's
--   collected
-- o Bob Dooling
-- o Robert Rowley for the awesome open source cms and README checks
--   http://www.irvineunderground.org
--
-- This file is released under the Nmap license; see:
--  http://nmap.org/book/man-legal.html
--
-- @args http-fingerprints.nikto-db-path Looks at the given path for nikto database.
--       It then converts the records in nikto's database into our Lua table format
--       and adds them to our current fingerprints if they don't exist already.
--       Unfortunately, our current implementation has some limitations:
--          * It doesn't support records with more than one 'dontmatch' patterns for
--            a probe.
--          * It doesn't support logical AND for the 'match' patterns.
--          * It doesn't support sending additional headers for a probe.
--       That means, if a nikto fingerprint needs one of the above features, it
--       won't be loaded. At the time of writing this, 6546 out of the 6573 Nikto
--       fingerprints are being loaded successfully.  This runtime Nikto fingerprint integration was suggested by Nikto co-author Chris Sullo as described at http://seclists.org/nmap-dev/2013/q4/292
--
-- Although this format was originally modeled after the Nikto format, that ended
-- up being too restrictive. The current format is a simple Lua table. There are many
-- advantages to this technique; it's powerful, we don't need to write custom parsing
-- code, anybody who codes in Lua can easily add checks, and we can write converters
-- to read Nikto and other formats if we want to.
--
-- The 'fingerprints' table is the key. It's an array of checks that will be run in the
-- order they're given. Each check consists of a path, zero or more matches, output text,
-- and other optional fields. Here are all the currently defined fields:
--
-- fingerprint.probes
-- A list of one or more probes to send to the server. Each probe is either a table containing
-- the key 'path' (and potentially others), or it's a string indicating the path.
--
-- fingerprint.probes[i].path
-- The URI to check, optionally containing GET arguments. This should start with a '/'
-- and, if it's a directory, end with a '/'.
--
-- fingerprint.probes[i].method [optional; default: 'GET'}}]
-- The HTTP method to use when making requests ('GET'}}, 'POST', 'HEAD', 'PUT', 'DELETE', etc
--
-- fingerprint.ignore_404 [optional; default: false]
-- If set, the automatic checks for 404 and custom 404 pages are disabled for that check.
-- Every page will be included unless fingerprint.matches.dontmatch excludes it.
--
-- fingerprint.severity [optional; default: 1]
-- Give a severity rating, if it's a vulnerability. The scale is:
-- 1 - Info
-- 2 - Low priority
-- 3 - Warning
-- 4 - Critical
--
-- fingerprint.matches
-- An array of tables, each of which contains three fields. These will be checked, starting
-- from the first, until one is matched. If there is no 'match' text, it will fire as long
-- as the result isn't a 404. This match is not case sensitive.
--
-- fingerprint.matches[i].match
-- A string (specifically, a Lua pattern) that has to be found somewhere in the output to
-- count as a match. The string can be in the status line, in a header, or in the body.
-- In addition to matching, this field can contain captures that'll be included in the
-- output. See: http://lua-users.org/wiki/PatternsTutorial
--
-- fingerprint.matches[i].dontmatch
-- A string (specifically, a lua pattern) that cannot be found somewhere in the output.
-- This takes precedence over any text matched in the 'match' field
--
-- fingerprint.matches[i].output
-- The text to output if this match happens. If the 'match' field contains captures, these
-- captures can be used with \1, \2, etc.
--
-- If you have any questions, feel free to email dev@nmap.org or contact Ron Bowes!
--
-- CHANGELOG:
-- Added 120 new signatures taken from exploit-db.com archives from July 2009 to July 2011 [Paulino Calderon]
-- Added the option to read nikto's database and make use of its fingerprints. [George Chatzisofroniou]
--

fingerprints = {};

------------------------------------------------
----           GENERAL CHECKS               ----
------------------------------------------------
-- These are checks for generic paths, like /wiki, /images, /admin, etc




table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/',
        method = 'GET'
      }
    },
    matches = {
      {
        match = '<title>Index of .*(Apache.*) Server at',
        output = '{directory listing}'
      },
      {
        match = '<title>Index of',
        output = '{directory listing}'
      }
    }
  });




table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/manager/',
        method = 'HEAD'
      },
      {
        path = '/admin.php',
        method = 'HEAD'
      },
      {
        path = '/admin/',
        method = 'HEAD'
      },
      {
        path = '/admin/admin/',
        method = 'HEAD'
      },
      {
        path = '/administrator/',
        method = 'HEAD'
      },
      {
        path = '/moderator/',
        method = 'HEAD'
      },
      {
        path = '/webadmin/',
        method = 'HEAD'
      },
      {
        path = '/adminarea/',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/',
        method = 'HEAD'
      },
      {
        path = '/adminLogin/',
        method = 'HEAD'
      },
      {
        path = '/admin_area/',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/',
        method = 'HEAD'
      },
      {
        path = '/instadmin/',
        method = 'HEAD'
      },
      {
        path = '/memberadmin/',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin/',
        method = 'HEAD'
      },
      {
        path = '/adm/',
        method = 'HEAD'
      },
      {
        path = '/admin/account.php',
        method = 'HEAD'
      },
      {
        path = '/admin/index.php',
        method = 'HEAD'
      },
      {
        path = '/admin/login.php',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.php',
        method = 'HEAD'
      },
      {
        path = '/joomla/administrator',
        method = 'HEAD'
      },
      {
        path = '/login.php',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.php',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.php',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.php',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/index.php',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.html',
        method = 'HEAD'
      },
      {
        path = '/admin/index.html',
        method = 'HEAD'
      },
      {
        path = '/admin/login.html',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.html',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.php',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.php',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.php',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.php',
        method = 'HEAD'
      },
      {
        path = '/admin/home.php',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.html',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.html',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.php',
        method = 'HEAD'
      },
      {
        path = '/admincp/',
        method = 'HEAD'
      },
      {
        path = '/admincp/index.asp',
        method = 'HEAD'
      },
      {
        path = '/admincp/index.html',
        method = 'HEAD'
      },
      {
        path = '/admincp/login.php',
        method = 'HEAD'
      },
      {
        path = '/admin/account.html',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.html',
        method = 'HEAD'
      },
      {
        path = '/webadmin.html',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.html',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.html',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.html',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.html',
        method = 'HEAD'
      },
      {
        path = '/admin_login.html',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.html',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.php',
        method = 'HEAD'
      },
      {
        path = '/cp.php',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.php',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.php',
        method = 'HEAD'
      },
      {
        path = '/nsw/admin/login.php',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.php',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.php',
        method = 'HEAD'
      },
      {
        path = '/admin_login.php',
        method = 'HEAD'
      },
      {
        path = '/administrator/account.php',
        method = 'HEAD'
      },
      {
        path = '/administrator.php',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.html',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.php',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.php',
        method = 'HEAD'
      },
      {
        path = '/admin-login.php',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.html',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.html',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.html',
        method = 'HEAD'
      },
      {
        path = '/admin/home.html',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/login.php',
        method = 'HEAD'
      },
      {
        path = '/moderator.php',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.php',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.php',
        method = 'HEAD'
      },
      {
        path = '/account.php',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.html',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.html',
        method = 'HEAD'
      },
      {
        path = '/admin-login.html',
        method = 'HEAD'
      },
      {
        path = '/controlpanel.php',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.php',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.html',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.html',
        method = 'HEAD'
      },
      {
        path = '/home.html',
        method = 'HEAD'
      },
      {
        path = '/rcjakar/admin/login.php',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.html',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.html',
        method = 'HEAD'
      },
      {
        path = '/webadmin.php',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.php',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.php',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.html',
        method = 'HEAD'
      },
      {
        path = '/admin.html',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.html',
        method = 'HEAD'
      },
      {
        path = '/cp.html',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.php',
        method = 'HEAD'
      },
      {
        path = '/moderator.html',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.html',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.html',
        method = 'HEAD'
      },

      {
        path = '/administrator/account.html',
        method = 'HEAD'
      },
      {
        path = '/administrator.html',
        method = 'HEAD'
      },

      {
        path = '/moderator/login.html',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.html',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.html',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.html',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/index.html',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.html',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.html',
        method = 'HEAD'
      },
      {
        path = '/adm/index.html',
        method = 'HEAD'
      },
      {
        path = '/adm.html',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.html',
        method = 'HEAD'
      },


      {
        path = '/controlpanel.html',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.html',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.php',
        method = 'HEAD'
      },

      {
        path = '/adminLogin.php',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.php',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.php',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.php',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.php',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.php',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.php',
        method = 'HEAD'
      },

      {
        path = '/modelsearch/admin.php',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.php',
        method = 'HEAD'
      },
      {
        path = '/adm/admloginuser.php',
        method = 'HEAD'
      },
      {
        path = '/admloginuser.php',
        method = 'HEAD'
      },
      {
        path = '/admin2.php',
        method = 'HEAD'
      },
      {
        path = '/admin2/login.php',
        method = 'HEAD'
      },
      {
        path = '/admin2/index.php',
        method = 'HEAD'
      },
      {
        path = '/adm/index.php',
        method = 'HEAD'
      },
      {
        path = '/adm.php',
        method = 'HEAD'
      },
      {
        path = '/affiliate.php',
        method = 'HEAD'
      },
      {
        path = '/adm_auth.php',
        method = 'HEAD'
      },
      {
        path = '/memberadmin.php',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin.php',
        method = 'HEAD'
      },

      {
        path = '/admin/account.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin_login.cfm',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.cfm',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.cfm',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.cfm',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admincp/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/admincp/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/moderator.cfm',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/adm/admloginuser.cfm',
        method = 'HEAD'
      },
      {
        path = '/adm.cfm',
        method = 'HEAD'
      },
      {
        path = '/adm_auth.cfm',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin.cfm',
        method = 'HEAD'
      },
      {
        path = '/webadmin.cfm',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.cfm',
        method = 'HEAD'
      },


      {
        path = '/administrator.cfm',
        method = 'HEAD'
      },
      {
        path = '/administrator/account.cfm',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.cfm',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin2/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/adm/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/memberadmin.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin2/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admloginuser.cfm',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.cfm',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.cfm',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.cfm',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.cfm',
        method = 'HEAD'
      },

      {
        path = '/controlpanel.cfm',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.cfm',
        method = 'HEAD'
      },

      {
        path = '/admin-login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin/home.cfm',
        method = 'HEAD'
      },
      {
        path = '/adm1n/',
        method = 'HEAD'
      },
      {
        path = '/4dm1n/',
        method = 'HEAD'
      },

      {
        path = '/admin/account.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/index.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.asp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.asp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.asp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/home.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.asp',
        method = 'HEAD'
      },
      {
        path = '/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin-login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.asp',
        method = 'HEAD'
      },

      {
        path = '/administrator/account.asp',
        method = 'HEAD'
      },
      {
        path = '/administrator.asp',
        method = 'HEAD'
      },

      {
        path = '/modelsearch/login.asp',
        method = 'HEAD'
      },
      {
        path = '/moderator.asp',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.asp',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.asp',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/controlpanel.asp',
        method = 'HEAD'
      },

      {
        path = '/admincp/login.asp',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.asp',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.asp',
        method = 'HEAD'
      },
      {
        path = '/webadmin.asp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.asp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin_login.asp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.asp',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.asp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.asp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.asp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.asp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/index.asp',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.asp',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.asp',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.asp',
        method = 'HEAD'
      },
      {
        path = '/adm/admloginuser.asp',
        method = 'HEAD'
      },
      {
        path = '/admloginuser.asp',
        method = 'HEAD'
      },
      {
        path = '/admin2.asp',
        method = 'HEAD'
      },
      {
        path = '/admin2/login.asp',
        method = 'HEAD'
      },
      {
        path = '/admin2/index.asp',
        method = 'HEAD'
      },
      {
        path = '/adm/index.asp',
        method = 'HEAD'
      },
      {
        path = '/adm.asp',
        method = 'HEAD'
      },
      {
        path = '/adm_auth.asp',
        method = 'HEAD'
      },
      {
        path = '/memberadmin.asp',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin.asp',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.asp',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/index.asp',
        method = 'HEAD'
      },
      {
        path = '/admin/account.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/home.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin-login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.aspx',
        method = 'HEAD'
      },
      {
        path = '/administrator/account.aspx',
        method = 'HEAD'
      },
      {
        path = '/administrator.aspx',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/moderator.aspx',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/controlpanel.aspx',
        method = 'HEAD'
      },
      {
        path = '/admincp/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/admincp/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.aspx',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.aspx',
        method = 'HEAD'
      },
      {
        path = '/webadmin.aspx',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin_login.aspx',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.aspx',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.aspx',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/adm/admloginuser.aspx',
        method = 'HEAD'
      },
      {
        path = '/admloginuser.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin2.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin2/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin2/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/adm/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/adm.aspx',
        method = 'HEAD'
      },
      {
        path = '/adm_auth.aspx',
        method = 'HEAD'
      },
      {
        path = '/memberadmin.aspx',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin.aspx',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.aspx',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/index.aspx',
        method = 'HEAD'
      },
      {
        path = '/admin/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin_area/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/home.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/controlpanel.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/pages/admin/admin-login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin-login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin-login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/cp.jsp',
        method = 'HEAD'
      },
      {
        path = '/administrator/account.jsp',
        method = 'HEAD'
      },
      {
        path = '/administrator.jsp',
        method = 'HEAD'
      },
      {
        path = '/moderator.jsp',
        method = 'HEAD'
      },
      {
        path = '/moderator/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/administrator/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/moderator/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/controlpanel.jsp',
        method = 'HEAD'
      },
      {
        path = '/admincp/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/admincp/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admincontrol.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/account.jsp',
        method = 'HEAD'
      },
      {
        path = '/adminpanel.jsp',
        method = 'HEAD'
      },
      {
        path = '/webadmin.jsp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/webadmin/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/admin_login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin_login.jsp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/adminLogin.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin/adminLogin.jsp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/adminarea/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/panel-administracion/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/modelsearch/admin.jsp',
        method = 'HEAD'
      },
      {
        path = '/administrator/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/admincontrol/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/adm/admloginuser.jsp',
        method = 'HEAD'
      },
      {
        path = '/admloginuser.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin2.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin2/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin2/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/adm/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/adm.jsp',
        method = 'HEAD'
      },
      {
        path = '/adm_auth.jsp',
        method = 'HEAD'
      },
      {
        path = '/memberadmin.jsp',
        method = 'HEAD'
      },
      {
        path = '/administratorlogin.jsp',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/login.jsp',
        method = 'HEAD'
      },
      {
        path = '/siteadmin/index.jsp',
        method = 'HEAD'
      },
      {
        path = '/admin1.php',
        method = 'HEAD'
      },
      {
        path = '/administr8.asp',
        method = 'HEAD'
      },
      {
        path = '/administr8.php',
        method = 'HEAD'
      },
      {
        path = '/administr8.jsp',
        method = 'HEAD'
      },
      {
        path = '/administr8.aspx',
        method = 'HEAD'
      },
      {
        path = '/administr8.cfm',
        method = 'HEAD'
      },
      {
        path = '/administr8/',
        method = 'HEAD'
      },
      {
        path = '/administer/',
        method = 'HEAD'
      },
      {
        path = '/administracao.php',
        method = 'HEAD'
      },
      {
        path = '/administracao.asp',
        method = 'HEAD'
      },
      {
        path = '/administracao.aspx',
        method = 'HEAD'
      },
      {
        path = '/administracao.cfm',
        method = 'HEAD'
      },
      {
        path = '/administracao.jsp',
        method = 'HEAD'
      },
      {
        path = '/administracion.php',
        method = 'HEAD'
      },
      {
        path = '/administracion.asp',
        method = 'HEAD'
      },
      {
        path = '/administracion.aspx',
        method = 'HEAD'
      },
      {
        path = '/administracion.jsp',
        method = 'HEAD'
      },
      {
        path = '/administracion.cfm',
        method = 'HEAD'
      },
      {
        path = '/administrators/',
        method = 'HEAD'
      },
      {
        path = '/adminpro/',
        method = 'HEAD'
      },
      {
        path = '/admins/',
        method = 'HEAD'
      },
      {
        path = '/admins.cfm',
        method = 'HEAD'
      },
      {
        path = '/admins.php',
        method = 'HEAD'
      },
      {
        path = '/admins.jsp',
        method = 'HEAD'
      },
      {
        path = '/admins.asp',
        method = 'HEAD'
      },
      {
        path = '/admins.aspx',
        method = 'HEAD'
      },
      {
        path = '/maintenance/',
        method = 'HEAD'
      },
      {
        path = '/Lotus_Domino_Admin/',
        method = 'HEAD'
      },
      {
        path = '/hpwebjetadmin/',
        method = 'HEAD'
      },
      {
        path = '/_admin/',
        method = 'HEAD'
      },
      {
        path = '/_administrator/',
        method = 'HEAD'
      },
      {
        path = '/_administrador/',
        method = 'HEAD'
      },
      {
        path = '/_admins/',
        method = 'HEAD'
      },
      {
        path = '/_administrators/',
        method = 'HEAD'
      },
      {
        path = '/_administradores/',
        method = 'HEAD'
      },
      {
        path = '/_administracion/',
        method = 'HEAD'
      },
      {
        path = '/_4dm1n/',
        method = 'HEAD'
      },
      {
        path = '/_adm1n/',
        method = 'HEAD'
      },
      {
        path = '/_Admin/',
        method = 'HEAD'
      },
      {
        path = '/system_administration/',
        method = 'HEAD'
      },
      {
        path = '/system-administration/',
        method = 'HEAD'
      },
      {
        path = '/system-admin/',
        method = 'HEAD'
      },
      {
        path = '/system-admins/',
        method = 'HEAD'
      },
      {
        path = '/system-administrators/',
        method = 'HEAD'
      },
      {
        path = '/administracion-sistema/',
        method = 'HEAD'
      },
      {
        path = '/Administracion/',
        method = 'HEAD'
      },
      {
        path = '/Admin/',
        method = 'HEAD'
      },
      {
        path = '/Administrator/',
        method = 'HEAD'
      },
      {
        path = '/Manager/',
        method = 'HEAD'
      },
      {
        path = '/Adm/',
        method = 'HEAD'
      },
      {
        path = '/systemadmin/',
        method = 'HEAD'
      },
      {
        path = '/AdminLogin.asp',
        method = 'HEAD'
      },
      {
        path = '/AdminLogin.php',
        method = 'HEAD'
      },
      {
        path = '/AdminLogin.jsp',
        method = 'HEAD'
      },
      {
        path = '/AdminLogin.aspx',
        method = 'HEAD'
      },
      {
        path = '/AdminLogin.cfm',
        method = 'HEAD'
      },
      {
        path = '/admin108/',
        method = 'HEAD'
      },
      {
        path = '/pec_admin/',
        method = 'HEAD'
      },
      {
        path = '/system/admin/',
        method = 'HEAD'
      },
      {
        path = '/plog-admin/',
        method = 'HEAD'
      },
      {
        path = '/ESAdmin/',
        method = 'HEAD'
      },
      {
        path = '/axis2-admin/',
        method = 'HEAD'
      },
      {
        path = '/admin_cp.asp',
        method = 'HEAD'
      },
      {
        path = '/sitecore/admin/',
        method = 'HEAD'
      },
      {
        path = '/sitecore/login/admin/',
        method = 'HEAD'
      }
    },
    matches = {
      
      {
        output = '{Admin Files}'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/backup/',
        method = 'GET'
      },
      {
        path = '/backup',
        method = 'GET'
      },
      {
        path = '/backup.sql',
        method = 'GET'
      },
      {
        path = '/backup.sql.gz',
        method = 'GET'
      },
      {
        path = '/backup.sql.bz2',
        method = 'GET'
      },
      {
        path = '/backup.zip',
        method = 'GET'
      },
      {
        path = '/backups/',
        method = 'GET'
      },
      {
        path = '/bak/',
        method = 'GET'
      },
      {
        path = '/back/',
        method = 'GET'
      },
      {
        path = '/cache/backup/',
        method = 'GET'
      },
      {
        path = '/admin/backup/',
        method = 'GET'
      },
      {
        path = '/dbbackup.txt',
        method = 'GET'
      }
    },
    matches = {
     
      {
        match = '',
        output = '{Backup Files}'
      }
    }
  });

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/b.sql',
        method = 'HEAD'
      },
      {
        path = '/db.sql',
        method = 'HEAD'
      },
      {
        path = '/ddb.sql',
        method = 'HEAD'
      },
      {
        path = '/users.sql',
        method = 'HEAD'
      },
      {
        path = '/database.sql',
        method = 'HEAD'
      },
      {
        path = '/mysql.sql',
        method = 'HEAD'
      },
      {
        path = '/dump.sql',
        method = 'HEAD'
      },
      {
        path = '/respaldo.sql',
        method = 'HEAD'
      },
      {
        path = '/data.sql',
        method = 'HEAD'
      },
      {
        path = '/old.sql',
        method = 'HEAD'
      },
      {
        path = '/usuarios.sql',
        method = 'HEAD'
      },
      {
        path = '/bdb.sql',
        method = 'HEAD'
      },
      {
        path = '/1.sql',
        method = 'HEAD'
      },
      {
        path = '/admin/download/backup.sql',
        method = 'HEAD'
      }

    },
    matches = {
      {
        match = '',
        output = '{Database Files}'
      }
    }
  });




table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/log/',
        method = 'HEAD'
      },
      {
        path = '/log.htm',
        method = 'HEAD'
      },
      {
        path = '/log.php',
        method = 'HEAD'
      },
      {
        path = '/log.asp',
        method = 'HEAD'
      },
      {
        path = '/log.aspx',
        method = 'HEAD'
      },
      {
        path = '/log.jsp',
        method = 'HEAD'
      },
      {
        path = '/logs/',
        method = 'HEAD'
      },
      {
        path = '/logs.htm',
        method = 'HEAD'
      },
      {
        path = '/logs.php',
        method = 'HEAD'
      },
      {
        path = '/logs.asp',
        method = 'HEAD'
      },
      {
        path = '/logs.aspx',
        method = 'HEAD'
      },
      {
        path = '/logs.jsp',
        method = 'HEAD'
      },
      {
        path = '/wwwlog/',
        method = 'HEAD'
      },
      {
        path = '/wwwlogs/',
        method = 'HEAD'
      },
      {
        path = '/mail_log_files/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        match = '',
        output = '{Log Files}'
      }
    }
  });


table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/robots.txt',
        method = 'HEAD'
      },
    },
    matches = {
      {
        match = '',
        output = '{Robots Files}'
      }
    }
  });







------------------------------------------------
----              DATABASES                 ----
------------------------------------------------

--phpmyadmin db taken from http://milw0rm.com/exploits/8921
table.insert(fingerprints, {
    category = 'database',
    probes = {
      {
        path = '/phpmyadmin/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin/',
        method = 'HEAD'
      },
      {
        path = '/PHPMyAdmin/',
        method = 'HEAD'
      },
      {
        path = '/PMA/',
        method = 'HEAD'
      },
      {
        path = '/pma/',
        method = 'HEAD'
      },
      {
        path = '/dbadmin/',
        method = 'HEAD'
      },
      {
        path = '/myadmin/',
        method = 'HEAD'
      },
      {
        path = '/php-my-admin/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.2.3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.2.6/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.4/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.5-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.5-rc2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.5/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.5-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.6-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.6-rc2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.6/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.7/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.5.7-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-alpha/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-alpha2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-beta1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-beta2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-rc2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-rc3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-pl2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.0-pl3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1-rc2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1-pl2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.1-pl3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.2-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.2-beta1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.2-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.3-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.3-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4-pl2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4-pl3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4-pl4/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.6.4/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.7.0-beta1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.7.0-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.7.0-pl1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.7.0-pl2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.7.0/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0-beta1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0-rc2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0.1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0.2/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0.3/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.0.4/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.1-rc1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.1/',
        method = 'HEAD'
      },
      {
        path = '/phpMyAdmin-2.8.2/',
        method = 'HEAD'
      },
      {
        path = '/sqlmanager/',
        method = 'HEAD'
      },
      {
        path = '/php-myadmin/',
        method = 'HEAD'
      },
      {
        path = '/phpmy-admin/',
        method = 'HEAD'
      },
      {
        path = '/mysqladmin/',
        method = 'HEAD'
      },
      {
        path = '/mysql-admin/',
        method = 'HEAD'
      },
      {
        path = '/websql/',
        method = 'HEAD'
      },
      {
        path = '/_phpmyadmin/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        output = '{Phpmyadmin Files}'
      }
    }
  });


------------------------------------------------
----              CUSTOM                 ----
------------------------------------------------

table.insert(fingerprints, {
    category = 'general',
    probes = {
      {
        path = '/.git/config/',
        method = 'HEAD'
      },
      {
        path = '/.hg/requires/',
        method = 'HEAD'
      },
      {
        path = '/.htaccess/',
        method = 'HEAD'
      },
      {
        path = '/.htpasswd/',
        method = 'HEAD'
      },
      {
        path = '/.svn/wc.db/',
        method = 'HEAD'
      },
      {
        path = '/CFIDE/adminapi/administrator.cfc/',
        method = 'HEAD'
      },
      {
        path = '/CFIDE/administrator/enter.cfm/',
        method = 'HEAD'
      },
      {
        path = '/CFIDE/administrator/index.cfm/',
        method = 'HEAD'
      },
      {
        path = '/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm',
        method = 'HEAD'
      },
      {
        path = '/access.log',
        method = 'HEAD'
      },
      {
        path = '/admin',
        method = 'HEAD'
      },
      {
        path = '/admin.nsf',
        method = 'HEAD'
      },
      {
        path = '/apc.php',
        method = 'HEAD'
      },
      {
        path = '/awstats',
        method = 'HEAD'
      },
      {
        path = '/backup.tar.gz',
        method = 'HEAD'
      },
      {
        path = '/backup/',
        method = 'HEAD'
      },
      {
        path = '/backups/',
        method = 'HEAD'
      },
      {
        path = '/bb-admin/',
        method = 'HEAD'
      },

      {
        path = '/cgi-bin/cvsweb/',
        method = 'HEAD'
      },
      {
        path = '/cgi-bin/php/',
        method = 'HEAD'
      },
      {
        path = '/cgi-bin/php5/',
        method = 'HEAD'
      },

      {
        path = '/crossdomain.xml',
        method = 'HEAD'
      },
      {
        path = '/error.log',
        method = 'HEAD'
      },
      {
        path = '/install/',
        method = 'HEAD'
      },
      {
        path = '/install/upgrade.php/',
        method = 'HEAD'
      },
      {
        path = '/jmx/console/',
        method = 'HEAD'
      },

      {
        path = '/pgmyadmin/',
        method = 'HEAD'
      },
      {
        path = '/phpMinfo.php/',
        method = 'HEAD'
      },
      {
        path = '/pls/admin/',
        method = 'HEAD'
      },
      {
        path = '/rockmongo/index.php',
        method = 'HEAD'
      },
      {
        path = '/server-status/',
        method = 'HEAD'
      },
      {
        path = '/trace.axd',
        method = 'HEAD'
      },
      {
        path = '/sites/default/files/backup_migrate/',
        method = 'HEAD'
      },
      {
        path = '/webmin/',
        method = 'HEAD'
      },
      {
        path = '/upload/',
        method = 'HEAD'
      },
      {
        path = '/uploads/',
        method = 'HEAD'
      }
    },
    matches = {
      {
        output = '{Custom Files}'
      }
    }
  });







local stdnse = require "stdnse"
local nmap = require "nmap"

nikto_db_path = stdnse.get_script_args("http-fingerprints.nikto-db-path") or "db_tests"
local f = nmap.fetchfile(nikto_db_path) or io.open(nikto_db_path, "r")

if f then

  stdnse.debug1("Found nikto db.")

  local nikto_db = {}
  for l in io.lines(nikto_db_path) do

    -- Skip comments.
    if not string.match(l, "^#.*") then

      record = {}

      for field in string.gmatch(l, "\"(.-)\",") do

        -- Grab every attribute and create a record.
        if field then
          string.gsub(field, '%%', '%%%%')
          table.insert(record, field)
        end
      end

      -- Make sure this record doesn't exists already.
      local exists = false
      for _, f in pairs(fingerprints) do
        if f.probes then
          for __, p in pairs(f.probes) do
            if p.path then
              if p.path == record[4] then
                exists = true
                break
              end
            end
          end
        end
      end

      -- What we have right now, is the following record:
      -- record[1]: Nikto test ID
      -- record[2]: OSVDB-ID
      -- record[3]: Server Type
      -- record[4]: URI
      -- record[5]: HTTP Method
      -- record[6]: Match 1
      -- record[7]: Match 1 (Or)
      -- record[8]: Match1 (And)
      -- record[9]: Fail 1
      -- record[10]: Fail 2
      -- record[11]: Summary
      -- record[12]: HTTP Data
      -- record[13]: Headers

      -- Is this a valid record?  Atm, with our current format we need
      -- to skip some nikto records. See NSEDoc for more info.

      if not exists
        and record[4]
        and record[8] == "" and record[10] == "" and record[12] == ""
        and (tonumber(record[4]) == nil or (tonumber(record[4]) and record[4] == "200")) then

        -- Our current format does not support HTTP code matching.
        if record[6] == "200" then record[6] = "" end

        nikto_fingerprint = { category = "nikto",
        probes = {
          {
            path = record[4],
            method = record[5]
          }
        },
        matches = {
          {
            dontmatch = record[9],
            match = record[6],
            output = record[11]
          },
        },
      }

      -- If there is a second match, add it.
      if record[7] and record[7] ~= "" then
        table.insert(nikto_fingerprint.matches, { match = record[7], output = record[11] })
      end

      table.insert(fingerprints, nikto_fingerprint)

    end
  end
end
end
