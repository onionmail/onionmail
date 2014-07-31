#!/bin/bash

if [ ! -d __MAILDIR__ ]; then
   echo "Server not generated!"
   exit
   fi

if [ "$1" = "stop" ]; then
  su __USER__ -c "java -jar \"__PATH__/onionmail.jar\" -f __PATH__/etc/config.conf -ndk --stop"
  exit
  fi

if [ "$1" = "start" ]; then
 su __USER__ -c "java -jar \"__PATH__/onionmail.jar\" -f __PATH__/etc/config.conf -ndk -p __PAR_PASSWD_BOOT__ > __PATH__/log/onionmail.log &"
 cpulimit -e java -b -l 10 -z
 exit
 fi

echo "Usage: onionmail stop | start"
