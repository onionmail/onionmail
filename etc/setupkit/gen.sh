#!/bin/bash

su __USER__ -c "java -jar /bin/onionmail.jar -f /etc/onionmail/config.conf -ndk -sp -p __PAR_PASSWD_BOOT__ --gen-servers"
chmod a=-,u=rwx -R __MAILDIR__
