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
  su __USER__ -c "java -jar /bin/onionmail.jar -f /etc/onionmail/config.conf -ndk --stop > /var/log/onionmail/stop.log"
  exit
  fi

if [ "$1" = "start" ]; then
	
	if [ ! -f __RAMPASS__ ]; then
		echo "Password not found in RAM"
		exit
		fi

 su __USER__ -c "java -jar /bin/onionmail.jar -f /etc/onionmail/config.conf -dr /var/log/onionmail/start.log -ndk -pi -ndk -ntx > /var/log/onionmail/onionmail.log < __RAMPASS__ &"
 __CPULIMIT__
 exit
 fi

echo "Usage: onionmail stop | start"
