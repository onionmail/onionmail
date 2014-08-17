#!/bin/bash

if [ `whoami` != "root" ]; then
  echo "You need the root access to OnionMail"
  exit
  fi
  
if [ ! -d __MAILDIR__ ]; then
   echo "Server not generated!"
   exit
   fi

if [ "$1" = "stop" ]; then
  su __USER__ -c "java -jar \"__PATH__/onionmail.jar\" -f __PATH__/etc/config.conf -ndk --stop > __PATH__/log/stop.log"
  exit
  fi

if [ "$1" = "start" ]; then
	
	if [ ! -f __RAMPASS__ ]; then
		echo "Password not found in __RAMPASS__"
		exit
		fi

 su __USER__ -c "java -jar \"__PATH__/onionmail.jar\" -f __PATH__/etc/config.conf -dr __PATH__/log/start.log -ndk -pi -ndk -ntx > __PATH__/log/onionmail.log < __RAMPASS__ &"
 __CPULIMIT__
 exit
 fi

echo "Usage: onionmail stop | start"
