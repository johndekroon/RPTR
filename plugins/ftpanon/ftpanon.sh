#!/bin/sh
HOST=$1
USER=anonymous
PASSWD=anonymous

ftp -n -v $HOST <<END_SCRIPT
quote USER $USER
quote PASS $PASSWD
quit
END_SCRIPT
exit 0
