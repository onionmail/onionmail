#!/bin/bash

su __USER__ -c "java -jar \"__PATH__/onionmail.jar\" -f __PATH__/etc/config.conf -ndk -sp -p __PAR_PASSWD_BOOT__ --gen-servers"
chmod a=-,u=rwx -R __MAILDIR__
