#!/bin/bash

px=`head -n 1 __RAMPASS__`
su __USER__ -c "java -jar /bin/onionmail.jar -f /etc/onionmail/config.conf -ndk -sp -p "${px}" --gen-servers"
px=0
chmod a=-,u=rwx -R __MAILDIR__
