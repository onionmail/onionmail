#!/usr/bin/python

#
# Copyright (C) 2014 by Tramaci.Org & OnionMail.info
# This file is a wizard to subscribe and configure onionmail in TAILS
# (PGP keys, VMAT address and etc...)
#
# onion.py is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This source code is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this source code; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import os
import socket
import string
import sys
import subprocess
import shutil
import time
import re
import socks
import tty

conf_version="0.3"
conf_home="/home/amnesia"
conf_base=conf_home+"/.claws-mail"
conf_certpath=conf_base+"/certs"
conf_accountrc=conf_base+"/accountrc"
conf_maildir=conf_base+"/profiles"
conf_gpg="gpg"
conf_infofile=conf_home+"/onionmail-info-account"
conf_tarprofile="profile.tar.gz"
conf_tarmail="maildir.tar.gz"
conf_clawsmail="/usr/local/bin/torified-claws-mail &"  #"claws-mail --online &"
conf_clawsexit="claws-mail --exit"
conf_mkpgp=1
conf_torport=9050
conf_torip="127.0.0.1"
conf_torrc="/etc/tor/torrc"
conf_saveinfo=1
conf_list="onionmail.lst"
conf_gpgcommentv="OnionMail VMAT address"
conf_tempath="/home/amnesia/.onionpy"

startpath=os.getcwd()
stat=1
ret="NOP"
USER=""
PEMCRT=""

DEFAULT_CONFIG="""
[Account: __number__]
account_name=__onionmail__
is_default=__is_default__
name=__username__
address=__onionmail__
organization=__nick__
protocol=0
receive_server=__onion__
smtp_server=__onion__
nntp_server=
local_mbox=/var/mail
use_mail_command=0
mail_command=/usr/sbin/sendmail -t -i
use_nntp_auth=0
use_nntp_auth_onconnect=0
user_id=__username__
password=__pop3password__
use_apop_auth=0
remove_mail=1
message_leave_time=7
message_leave_hour=0
enable_size_limit=0
size_limit=1024
filter_on_receive=1
filterhook_on_receive=1
imap_auth_method=0
receive_at_get_all=1
max_news_articles=300
inbox=#mh/__mhinbox__/inbox
local_inbox=#mh/__mhinbox__/inbox
imap_directory=
imap_subsonly=1
low_bandwidth=0
generate_msgid=1
generate_xmailer=1
add_custom_header=0
msgid_with_addr=0
use_smtp_auth=1
smtp_auth_method=16
smtp_user_id=__username__
smtp_password=__smtppassword__
pop_before_smtp=0
pop_before_smtp_timeout=5
signature_type=0
signature_path=
auto_signature=0
signature_separator=-- 
set_autocc=0
auto_cc=
set_autobcc=0
auto_bcc=
set_autoreplyto=0
auto_replyto=
enable_default_dictionary=0
default_dictionary=de
enable_default_alt_dictionary=0
default_alt_dictionary=de
compose_with_format=0
compose_subject_format=
compose_body_format=
reply_with_format=0
reply_quotemark=
reply_body_format=
forward_with_format=0
forward_quotemark=
forward_body_format=
default_privacy_system=
default_encrypt=0
default_encrypt_reply=1
default_sign=0
default_sign_reply=0
save_clear_text=0
encrypt_to_self=0
privacy_prefs=gpg=REVGQVVMVA==
ssl_pop=2
ssl_imap=0
ssl_nntp=0
ssl_smtp=2
use_nonblocking_ssl=1
in_ssl_client_cert_file=
in_ssl_client_cert_pass=!
out_ssl_client_cert_file=
out_ssl_client_cert_pass=!
set_smtpport=1
smtp_port=25
set_popport=1
pop_port=110
set_imapport=0
imap_port=143
set_nntpport=0
nntp_port=119
set_domain=0
domain=
gnutls_set_priority=0
gnutls_priority=
mark_crosspost_read=0
crosspost_color=0
set_sent_folder=0
sent_folder=
set_queue_folder=0
queue_folder=
set_draft_folder=0
draft_folder=
set_trash_folder=0
trash_folder=
imap_use_trash=1
"""

DEFAULT_FOLDERLIST="""
    <folder type="mh" path="__BOXNAME__" sort="0" collapsed="0" name="__BOXNAME__">
        <folderitem last_seen="0" order="0" watched="0" ignore="0" locked="0" forwarded="0" replied="0" total="0" marked="0" unreadmarked="0" unread="0" new="0" mtime="__TIMESTAMP__" sort_type="ascending" sort_key="date" hidedelmsgs="0" hidereadmsgs="0" threaded="1" thread_collapsed="0" collapsed="0" path="trash" name="trash" type="trash" />
        <folderitem last_seen="0" order="0" watched="0" ignore="0" locked="0" forwarded="0" replied="0" total="0" marked="0" unreadmarked="0" unread="0" new="0" mtime="__TIMESTAMP__" sort_type="ascending" sort_key="date" hidedelmsgs="0" hidereadmsgs="0" threaded="1" thread_collapsed="0" collapsed="0" path="draft" name="draft" type="draft" />
        <folderitem last_seen="0" order="0" watched="0" ignore="0" locked="0" forwarded="0" replied="0" total="0" marked="0" unreadmarked="0" unread="0" new="0" mtime="__TIMESTAMP__" sort_type="ascending" sort_key="date" hidedelmsgs="0" hidereadmsgs="0" threaded="1" thread_collapsed="0" collapsed="0" path="queue" name="queue" type="queue" />
        <folderitem last_seen="0" order="0" watched="0" ignore="0" locked="0" forwarded="0" replied="0" total="0" marked="0" unreadmarked="0" unread="0" new="0" mtime="__TIMESTAMP__" sort_type="ascending" sort_key="date" hidedelmsgs="0" hidereadmsgs="0" threaded="1" thread_collapsed="0" collapsed="0" path="sent" name="sent" type="outbox" />
        <folderitem last_seen="0" order="0" watched="0" ignore="0" locked="0" forwarded="0" replied="0" total="0" marked="0" unreadmarked="0" unread="0" new="0" mtime="__TIMESTAMP__" sort_type="ascending" sort_key="date" hidedelmsgs="0" hidereadmsgs="0" threaded="1" thread_collapsed="0" collapsed="0" path="inbox" name="inbox" type="inbox" />
    </folder>
"""

Col = {}
Col["0"] = "\033[0m"    
Col["red"] = "\033[0;31m"         
Col["green"] = "\033[0;32m"       
Col["yellow"] = "\033[0;33m"     
Col["blue"] = "\033[0;34m"       
Col["purple"] = "\033[0;35m"     
Col["cyan"] = "\033[0;36m"       
Col["white"] = "\033[0;37m"       
Col["ored"] = "\033[41m"     
Col["ogreen"] = "\033[42m"     
Col["oyellow"] = "\033[43m"     
Col["oblue"] = "\033[44m"       
Col["opurple"] = "\033[45m"    
Col["ocyan"] = "\033[46m"      

PGPkey="""
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFOAlMcBCAC+wkTButileTiDjr50NYLspDF1Etk3hyFssAG8rALJVifb8inX
e/J7vYUf8EsrWL/FR1iOQbjDrwjzI5r9b5TZN5wmgroVaqiJKGe/e1VllRBpazn9
ie0eunj2Kjvu1YCVb1+Mixf3/Dg8RIMkArJDzNCqYz7FyM75fsZLWlppM46vLFLf
E6NPzcsg19S/8bhjOxMemz3PbbVxGdiTne8qH9V6w8a4HV7sGqiiXumPQgvYp4On
0bxzOh1ZINcC3WFMX3eiH7UEIF8crukoksAQ93s9cxCfw6u7qtZrMsXdrjQ3Ooym
e4r8Wf1G9MBd/0o43hKQi+iqlr003YEJE9V7ABEBAAG0Yk9uaW9uTWFpbCBOZXR3
b3JrIEFwcGxpY2F0aW9uIChPbmlvbk1haWwgTmV0d29yayBhcHBsaWNhdGlvbikg
PG5ldHdvcmsuYXBwQGxvdWhsYmd5dXBna3Rzdzcub25pb24+iQE2BBMBAgAgBQJT
gJTHAhsPBgsJCAcDAgQVAggDBBYCAwECHgECF4AACgkQkRuYZnag/amWawgAk6VX
V1kBC4EwRgkt4/R+mn7wSB12bCvK1ldCjedXbLydCT1O4P9gW7aVJHm3Xs6xD9cx
l7weAIPCGNaszAf0mJqrUunJ8mpYqzTa2QaQpLQTbGljin5NK0iQlddtluJ0tIcu
n7EKLiQ3fCMj9IXxkmRFy6RTW9f9jBNm5iXD2UYz98wlJa/paEs4ABsyjswqK0VV
bQvep41s/ruZl07bi0Tdi6ZU/SCFxyn+Egw0KBARROS/sUGS9gHCNL7hE83bZOS/
kK8Bqdb4lgOm8lmy1KqL0yVt7PnGF/7+iFont6yhUFIyKoXSwHXRQT8RcmStjucA
fzajq8SWv9iM65gqLIkCHAQTAQIABgUCU4CVrgAKCRDJxSQSgoghaxALD/930uXF
jMVbOVJzZCOF3lE2sg2dkDJE4RSbRUuRdEKg9rQUK2KxWM9JFp4b3JpTSvum0B4O
bnezjBbEYabwya3/xYCw5QmCJfu67b7diUtSMs4uVLV16Q0AvULRcjSnINLY6v7C
HJV103znU9xq4V3axMw8ypT8+jQpmNVs1htArTzb4/Lx51GwQo0jhR79kKCGbBe1
RmKjeKNqJb57YEVW2YnpqYRwn/NxlyXgRkcU6M1wivTXTdG7Fva+/2cEHnTVILsW
CoBkDgL2nLA8fVErVyiC5OJU+jUmdaAG8uU0O/EyrLHn15oZgmEbEnY5RQarQckp
LW5AtfXl2mvzhHS0j1nR2W2ih9Mo8UjHz5Gbwi6iyzUzkynSxKFs2RyCST8ZpQm1
ySZ11KhIwyK7VLw42v9detBkSQ1KMhVuHUJ4jKOZ39rqmjtQEf5RHNZ9FsjjT/oZ
afmr0idnTe3+KGiZz/GYA6dmvbNbMQjZ60zbKLxVmGyeC7CqGMwVeGI7JucB0E67
uKCBqBCeZ6IRPOCDL5tTaiwMTZf6pqXutrDcKBTQUIP3PejivBLEGWoWgW8LA83s
PlI6+cUsdUV2QdB7q4LE+bHMnOMxBu23pGEDv6fd4Ppsgu5t+2Pyb8hk+dOLTwIL
UTWOect0S+GEQ8Ey+K6QCefEX03846vccP6Z+w==
=TTj4
-----END PGP PUBLIC KEY BLOCK-----
"""
PGPkey=PGPkey+"\032\n"
PGPFir="A9CD12C1F84476DB879DF642911B986676A0FDA9"
PGPId="911B986676A0FDA9"
MainServer="http://louhlbgyupgktsw7.onion/network/"

FinalInfo="""

"""

class PException(Exception): pass

def download(out):
	outasc=out+".asc"
	cmd="wget \""+MainServer+outasc+"\" -q -t 2 -U \"onion.py (TAILS)\" -O "+outasc
	p = subprocess.Popen(cmd,shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
	if p.wait()!=0:
		ferro("Can't download from "+MainServer)

	cmd="gpg --status-fd=2 --no-verbose --batch --quiet --output - --verify "+outasc
	p = subprocess.Popen(cmd,shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
	rs = p.stdout.read()
	if p.wait()!=0:
		ferro("Invalid signature in file outasc")

	rs=string.upper(rs)
	rs=string.replace(rs," ","")
	rs=string.split(rs,"\n")
	pa=0
	pb=0
	pat1="[GNUPG:]GOODSIG"+PGPId
	pat2="[GNUPG:]VALIDSIG"+PGPFir
	for line in rs:
		if string.find(line,pat1)!=-1:
			pa=1
		if string.find(line,pat2)!=-1:
			pb=1

	if pa==0 or pb==0:
		print "\t",Col["red"],"Sign error ", pa, bp, Col["0"]
		ferro("This file is not signed by "+PGPId)
	
	cmd="gpg --status-fd=2 --no-verbose --quiet --batch --output "+out+" --decrypt "+outasc
	p = subprocess.Popen(cmd,shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
	if p.wait()!=0:
		ferro("Can't decrypt "+outasc)

	if not os.path.isfile(out):
		ferro("Can't decrypt "+out)

	os.remove(outasc)
		

def importmypgp():
	p = subprocess.Popen("gpg --batch --yes --import",shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 	stdin=subprocess.PIPE)
	p.stdin.write(PGPkey)
	p.stdin.close()
	if p.wait()!=0:
		ferro("Can't import my PGP key! All downloaded data will be insecure!")

def inittheclaws():
    if os.path.exists(conf_base)==False or os.path.isfile(conf_base+"/folderlist.xml")==False:
        print Col["cyan"]+"Building the Claws-Mail's profile"+Col["0"]

        if os.path.exists(conf_base)==False:
		os.makedirs(conf_base)

        p = subprocess.Popen("tar -xf "+conf_tarprofile+" -C "+conf_base + " > /dev/null", shell=True)
        ret = p.wait()
        if ret==0:
            print "\t" + Col["blue"]+"Done!!!"+Col["0"]
        else:
            print "\t" + Col["red"]+"Error "+str(ret)+Col["0"]
            sys.exit(1)

# def parsetor():  # Used in anther distro
#     "Parse torrc and get the tor SOCKS proxy"
#     global conf_torport
#     global conf_torip
#     
#     fh = open(conf_torrc,"r")
#     li = fh.read()
#     fh.close()
#     li = string.replace(li,"\r\n","\n")
#     li = string.split(li,"\n")
#     fh=""
#     for ln in li:
#         tok = string.split(ln,"#",2)
#         ln=tok[0]
#         fh = fh + string.strip(ln) + "\n"
#     
#     fh = string.lower(fh)
#     fh1 = re.search( r'^\s*socksport\s+(?P<port>[0-9]{1,5})' , fh)
#     if fh1:
#         fh1 = fh1.groupdict()
#         conf_torport=fh1["port"]
#     
#     fh1 = re.search( r'^\s*sockslistenaddress\+(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' , fh)
#     if fh1:
#         fh1 = fh1.groupdict()
#         fh1 = fh1["ip"]
#         ip = string.split(fh1,".")
#         if ip[3]!="0" and ip[0]!="0":
#             conf_torip=fh1

def creategpgkey(mail,name,bits,passwd):
    "Generates a PGP key via gpg"
    cmd = "--batch --gen-key --yes"
    sti ="Key-Type: RSA\n"
    sti = sti + "Key-Length: "+str(bits)+"\n"
    sti = sti + "Passphrase: "+passwd+"\n"
    sti = sti + "Expire-Date: 0\n"
    sti = sti + "Subkey-Length: "+str(bits)+"\n"
    sti = sti + "Subkey-Type: RSA\n"
    sti = sti + "Name-Real: "+name+"\n"
    sti = sti + "Name-Email: "+mail+"\n"
    sti = sti + "%commit\n"
    sti = sti + "%save\n"
    sti = sti + "%echo done\n"
    sti = sti + "\031\n\n"

    p = subprocess.Popen(conf_gpg+" "+cmd,shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
    p.stdin.write(sti)
    return p.wait()

def addgpguid(curmail,newmail,name,passwd,comment):
	cmd="gpg --yes --passphrase-fd 0 --command-fd 0 --batch --edit-key \""+curmail+"\" adduid save"
	sti=passwd+"\n"+name+"\n"+newmail+"\n"+comment+"\n"
	p = subprocess.Popen(cmd,shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
	p.stdin.write(sti)
	rs=p.wait()
	return rs
    
def perro(st):
    "Do an error on stat=0 (this is not a spanish dog!)"
    if stat==0:
        print Col["red"] + st + Col["0"]
        sok.close()
        raise PException("PERRO")

def writedata(dta):
    "Sends multiline data in POP3 protocol"
    dta=string.strip(dta)
    if dta!="":
        dta=string.replace(dta,"\r\n","\n")
        dta=string.replace(dta,"\r","")
        dta=string.split(dta,"\n")
        for lin in dta:
            send(lin)
            
    send(".")
            
def rdln():
    "Read a line from raw socket"
    i = 0
    li=""
    while i<80:
        ch = sok.recv(1)
        if ch=="\r":
            break
    
        if ch!="\n":
            li = li + ch
        
        i = i +1
    return li

def rdcmd():
    "Read a cmd result"
    global stat
    global ret
    
    data = rdln()
    tok = string.split(data," ")
    if len(tok) <2:
        ret=""
    else:
        ret=tok[1]

    if tok[0]=="+OK":
        stat=1
    else:
        stat=0
    return tok

def rdcmdm():
    "This read a multi line POP3 command return"
    st = rdcmd()
    if ret==0:
        return ""
    i=0
    rs=""
    while i<4000:
        i = i+1
        li = rdln()
        if li == ".":
            break
        rs = rs+li+"\n"
    return rs

def send(cmd):
    "Send a POP3 command"
    st=cmd+"\r\n"
    sok.sendall(st)

def parseheaders(dta):
    "Parse a string as headers"
    dta=string.strip(dta)
    dta=string.replace(dta,"\r\n","\n")
    dta=string.split(dta,"\n")
    hldr = {}
    for cli in dta:
        if string.find(cli,":") != -1:
            tok = string.split(cli,":",2)
            tok[0] = string.strip(tok[0])
            tok[1] = string.strip(tok[1])
            tok[0] = string.lower(tok[0])
            hldr[tok[0]]=tok[1]
    
    return hldr

def replacer(orig,hldr):
    "Replace __key__ from hldr"
    rs=orig
    for key in hldr:
        k1 = "__"+key+"__"
        rs=string.replace(rs,k1,hldr[key])
    return rs

def folderxml(fil,nam):
	fh = open(fil,"r")
	li = fh.read()
	fh.close()
	xmlc = DEFAULT_FOLDERLIST
	par={
		"TIMESTAMP"	: str(int(time.time())) ,
		"BOXNAME"	: nam			}
	
	xmlc = replacer(xmlc, par)
	li=string.replace(li,"</folderlist>",xmlc)
	li=li+"</folderlist>"
	fh = open(fil,"w")
	fh.write(li)
	fh.close()

def ferro(st):
    "Force an error (This is not an italian metal!)"
    if st=="":
        st="Invalid USER data from server"
    print "\n"+Col["ored"]+st+Col["0"]
    raise PException("FERRO")

def checkuser():
    "Test user data"
    global USER
    ma = re.match(r'^[a-z0-9]{16}\.onion$',USER["onion"])
    if ma==False:
        ferro("")
    
    ma = re.match(r'^[a-z0-9\_\-\.]{1,40}\@[a-z0-9]{16}\.onion$',USER["onionmail"])
    if ma==False:
        ferro("")
    
    ma = re.match(r'^[a-z0-9\-\_\.]{1,40}$',USER["username"])
    if ma==False:
        ferro("")

def configuser():
    "Configure claws-mail"
    global USER
    USER["inbox"]=conf_maildir+"/201"
    USER["number"]="201"
    USER["is_default"]="0"

    if os.path.isfile(conf_accountrc):
	conf = open(conf_accountrc,"r")
    	dt = conf.read()
    	conf.close()
    else:
	dt=""

    for index in range(1,200):
        if string.find(dt,"[Account: " + str(index)+"]")==-1:
            USER["number"] = str(index)
            if not os.path.exists(conf_home + "/OnionMailBox"+USER["number"]):
            	break

    USER["inbox"]=conf_home + "/OnionMailBox"+USER["number"]
    USER["mhinbox"]="OnionMailBox"+USER["number"]

    ua = DEFAULT_CONFIG
    ua = replacer(ua,USER)
    dt = dt + ua
    ua=""

    conf = open(conf_accountrc,"w")
    conf.write(dt)
    conf.close()
    
    os.makedirs(USER["inbox"])
    p = subprocess.Popen("tar -xf "+conf_tarmail+" -C "+USER["inbox"] +" > /dev/null", shell=True)
    ret = p.wait()
    if ret!=0:
        ferro("Error 1/"+str(ret))

    tagsdb=conf_base+"/tagsdb/#mh/"+USER["mhinbox"]
    p = subprocess.Popen("mv -f "+USER["inbox"]+"/__tagsdb "+tagsdb+" > /dev/null",shell=True); 
    if ret!=0:
        ferro("Error 2/"+str(ret))

    folderxml(conf_base+"/folderlist.xml",USER["mhinbox"]);

def configssl(outp, pemcrt):
    "Config SSL certificate"
    temp="/tmp/onionsetup"+str(time.time())+".tmp"
    fi = open(temp,"w")
    fi.write(pemcrt)
    fi.close()
    p = subprocess.Popen("openssl x509 -in "+temp+" -inform PEM -out "+temp+".out -outform DER", shell=True)
    ret = p.wait()
    os.remove(temp)
    temp=temp+".out"
    if os.path.exists(conf_certpath)==False:
        os.makedirs(conf_certpath)

    shutil.copyfile(temp,conf_certpath+"/"+outp+".25.cert")
    shutil.move(temp,conf_certpath+"/"+outp+".110.cert")
    return ret

def onionmail(hiddenserv):
	global stat
	global ret
	global sok
	global USER
	global PEMCRT
	
	print Col["purple"] + "Connecting to hidden service '"+Col["cyan"]+hiddenserv+Col["purple"]+"' ..."+Col["0"]
	try:
		socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,"127.0.0.1",9050,True)  #torConf
		sok = socks.socksocket()
		sok.connect((hiddenserv,110))
	except IOError:
		print Col["ored"]+"\tError: Can't connect to this hidden service!"+Col["0"]
		raise

	print "\t"+Col["blue"]+"Connected!!!"+Col["0"]

	rs = rdcmd()
	perro("Error on POP3 server")

	send("CAPA")
	rs = rdcmdm()
	perro("Error in POP3 session")

	if string.find(rs,"\nRQUS\n") == -1:
	    send("QUIT")
	    rs = rdcmd()
	    sok.close()
	    print Col["ored"]+"This server doesn't support RQUS"+Col["0"]
	    raise PException("PERRO")

	print Col["cyan"]+"New user request"+Col["0"]    
	print Col["purple"]+"Now the server may ask a CAPTCHA code."
	print "You will be shown a picture in ascii art, you will need to recognize the characters and enter the code."+Col["0"]
	print Col["red"]+"Be careful there may be some strange symbols to ignore."+Col["0"]
	print Col["red"]+"Please wait to otherside reply after press return.\nSometime the hidden services may be slow.\n"+Col["0"]
	print Col["purple"]+"Press return to continue"+Col["0"]
	cp = sys.stdin.readline()
	send("RQUS");
	while 1:
	    rs=rdcmdm()
	    if ret!="CAPTCHA":
		perro("Too many error")
		break

	    print rs
	    print Col["purple"] + "Enter CAPTCHA:"+Col["0"]
	    cp = sys.stdin.readline()
	    cp = string.strip(cp)
	    send(cp)

	print Col["cyan"]+"If you've got an invite voucher code enter it now.\n\tOtherwise, leave a blank line."+Col["0"]
	print Col["purple"]+"Enter voucher code:"+Col["0"]
	cp = sys.stdin.readline()
	cp = string.strip(cp)
	send(cp)
	rs=rdcmd()
	perro("Operation not permitted to this server")

	while 1:
	    print Col["purple"]+"Enter Username:"+Col["0"]
	    cp = sys.stdin.readline()
	    cp = string.strip(cp)
	    send(cp)
	    rs=rdcmd()
	    if ret!="USERNAME":
		perro("Too many error")
		break

	print Col["cyan"]+"The server is creating the new user, please wait..."+Col["0"]
	print "\t"+Col["cyan"]+"The current operations can take several minutes..."+Col["0"]
	writedata("")    
	USER=rdcmdm()
	perro("User subscription error")
	print "\t"+Col["purple"]+"Done!!!"+Col["0"]

	print Col["cyan"]+"Configuring Claws-Mail ..."

	USER=parseheaders(USER)
	checkuser()
	configuser()

	send("PEM")
	PEMCRT=rdcmdm()
	sok.close()

	cp = configssl(USER["onion"],PEMCRT)
	if cp!=0:
	    print Col["ored"] + "Error on SSL configuration"+Col["0"]
	    print Col["red"] + "Check the SSL certificate manually"+Col["0"]
	    print "\t"+Col["blue"]+"SHA1: "+Col["yellow"]+USER["sha1"]+Col["0"]
	    
	print "\t"+Col["purple"]+"Done!!!"+Col["0"]

	if conf_mkpgp!=0:
	    print Col["cyan"]+"Generating a new PGP key"+Col["0"]
	    os.system("stty -echo")
	    
	    while 1:
		print Col["purple"]+"Enter the passphrase:"+Col["0"]
		pha1 = sys.stdin.readline()
		pha1 = string.strip(pha1)
		sys.stdout.write(Col["yellow"])
		for cp in xrange(len(pha1)):
		    sys.stdout.write("*")
		
		print Col["0"]
		print Col["purple"]+"Enter the passphrase again:"+Col["0"]
		pha2 = sys.stdin.readline()
		pha2 = string.strip(pha2)
		sys.stdout.write(Col["yellow"])
		for cp in xrange(len(pha2)):
		    sys.stdout.write("*")
		
		print Col["0"]
		if pha1==pha2:
		    break
		
		print Col["ored"]+"ERROR!"+Col["0"]
		print Col["red"]+"Retry"+Col["0"]

	    os.system("stty echo")

	    while 1:
		print Col["purple"]+"Enter your name:"+Col["0"]
		print Col["purple"]+"Leave blank if you want \"anonymous user\""+Col["0"]
		pha2 = sys.stdin.readline()
		pha2 = string.strip(pha2)
		if len(pha2)==0:
			pha2="Anonymous User"

		if len(pha2)>8:
		    break
		
		print Col["red"]+"Too short! Min. = 8 char."+Col["0"]
	
	if conf_saveinfo==1:
		inf=""
		for key in USER:
		    inf = inf + key + " =\t" + USER[key] + "\n"

		conf=open(conf_infofile+USER["number"]+".txt","w")
		conf.write(inf)
		conf.close()

	if conf_mkpgp!=0:
	    print Col["purple"]+"Choose the key size"+Col["0"]
	    print "\t",Col["cyan"],"(1)",Col["green"]," = ", Col["blue"] , "2048 bits\tNormal",Col["0"]
	    print "\t",Col["cyan"],"(2)",Col["green"]," = ", Col["yellow"] , "4096 bits\tGood",Col["0"]
	    print "\t",Col["cyan"],"(3)",Col["green"]," = ", Col["green"] , "8192 bits\tStrong",Col["0"]
	    print "\t",Col["cyan"],"(4)",Col["green"]," = ", Col["red"] , "16384 bits\tVery strong",Col["0"]
	    inf = { "1" : 2048 , "2": 4096, "3" : 8192, "4" : 16384 }
	    while 1:
		print "> ",
		bits=sys.stdin.readline()
		bits=string.strip(bits)
		if bits in inf:
			bits=inf[bits]
			break			
	    print Col["cyan"]+"I'm building a new PGP key (",bits," bits).\n\tWait a few minutes...\n\tThe processing is very complex."+Col["0"]
	    ret = creategpgkey(USER["onionmail"],pha2,bits,pha1)
	    print "\t",str(ret)," ",Col["blue"],"Done!!!",Col["0"]

	    if "vmatmail" in USER:
		print Col["cyan"]+"Add new uid to VMAT address..."+Col["0"]
		ret = addgpguid(USER["onionmail"],USER["vmatmail"],pha2,pha1,conf_gpgcommentv)
		print "\t",str(ret)," ",Col["blue"],"Done!!!",Col["0"]

	    pha2=""
	    pha1=""

	print Col["cyan"]+"Account "+Col["green"]+USER["username"]+Col["cyan"]+" created successfully"+Col["0"]
	print Col["cyan"]+"Sending GPG keys to keyservers..."+Col["0"]
	os.system("gpg -no-tty --batch --send-keys")
	print Col["cyan"]+"Press enter to continue."+Col["0"]
	cp = sys.stdin.readline()
	print "\033[2J\033[0;0H\n"	
	print Col["purple"]+"Your email account has been successfully activated."+Col["0"]
	print "Your email address is ",USER["onionmail"]
	if "vmatmail" in USER:
		print Col["cyan"]+"A VMAT virtual address is now active:"+Col["0"]
		print Col["purple"]+"Your address now appear:"+Col["0"]
		print "\t"+USER["vmatmail"];
		print Col["purple"]+"This address is used in Internet and Tor networks"+Col["0"],"\n"
	else:
		print Col["yellow"]+"Do not have an address VMAT, read the manual to know how to do."+Col["0"]
		print Col["purple"]+"Your address will translated to Internet compatibility via MAT protocol."+Col["0"],"\n"

	if conf_saveinfo==1:
		print Col["purple"]+"All your account information has been saved to this file:"+Col["0"]
		print "\t"+conf_infofile+USER["number"]+".txt"
	
	print "\nSend a message to your server with subject the word \"RULEZ\" to get more help."
	print "Server address:",Col["cyan"]+"server@"+USER["onion"],Col["0"]
	print "Server administators:",Col["cyan"]+"sysop@"+USER["onion"],Col["0"]
	print "\n"+Col["red"]+"Remember to send your public keys to keyservers."+Col["0"]
	print "\tUse the menu': System -> Preferences -> Password and Encryption Keys"
	print "\nNow you can open Claws-Mail, everything should already be configured."
	print "If you want to activate another OnionMail, run this program again."
	print Col["purple"]+"See http://onionmail.info to get more information.",Col["0"]+"\n"
	print Col["cyan"]+"Press enter to continue.",Col["0"]
	cp = sys.stdin.readline()
	print "\033[2J\033[0;0H\n"	
	if conf_clawsmail!="":
		os.system(conf_clawsmail)
	
	print "\033[2J\033[0;0H\n"	
	print Col["cyan"]+"Setup wizard complete..."+Col["0"]+"\n"
	print Col["cyan"]+" Now you can delete files"+Col["0"]
	print "\tmaildir.tar.gz"
	print "\tprofile.tar.gz"
	print "\tonionmail.lst\n"

	print "\t\"In the future, maybe we will implement the anonymous coffee!"
	print "\t\tToday, only OnionMail ;)\" \n"
	print "\n\n\nPress return to close."
	cp = sys.stdin.readline()

def adj(st,sz):
	if len(st)>sz:
		st=st[0:sz]
	return string.ljust(st,sz)+" "

def serverlist():
	fd = open(conf_list,"r")
	conf = fd.read()
	fd.close()
	conf = string.strip(conf)
	conf = string.split(conf,"\n")
	lst=[]
	for cli in conf:
		tok = string.split(cli,",")
		if len(tok)==4:
			lst.append({"nick":tok[0] , "onion":tok[1], "flg":tok[2],"per":int(tok[3]) ,"grp":"-"})

		if len(tok)==5:
			lst.append({"nick":tok[0] , "onion":tok[1], "flg":tok[2],"per":int(tok[3]) ,"grp":tok[4]})

	print "\033[2J\033[0;0H"+Col["purple"]+"Select an OnionMail server:"+Col["0"]
	print " "+ adj("Opt.",5)+ adj("Nick name",20) + adj("Group",14)+ adj("Address",22) + "Status"
	for index in range(len(lst)):
		cur = lst[index]
		ava = Col["red"]+"DISAB."

		if cur["per"]==0:
			ava=Col["red"] + "N/A"

		if cur["per"]==0 and cur["flg"]=="V":
			ava=Col["yellow"] + "VOUCHER"

		if cur["per"]>1 and cur["per"]<25:
			ava=Col["yellow"] + str(cur["per"])
	
		if cur["per"]>24 and cur["per"]<51:
			ava=str(cur["per"])
	
		if cur["per"]>50:
			ava=Col["green"] + str(cur["per"])

		print " "+Col["purple"] + adj("(" +str(index+1) + ")",5)+Col["cyan"]+ adj(cur["nick"],20) + Col["cyan"] + adj(cur["grp"],14)+ Col["blue"] + adj(cur["onion"],22) + ava + Col["0"]
	
		if (index%23)==22:
			os.system("stty -echo")			
			print Col["cyan"],"Scroll?",Col["0"]
			pha2 = sys.stdin.readline()
			os.system("stty echo")
			print " "+ adj("Opt.",5)+ adj("Nick name",20) + adj("Group",14)+ adj("Address",22) + "Status"

	hserv=""
	print " "+Col["purple"] + adj("(^C)",5)+Col["cyan"]+ "Exit wizard."+ Col["0"]	

	while 1:
		print Col["cyan"]+"> "+Col["0"],
		pha2 = sys.stdin.readline()
		pha2 = string.strip(pha2)
		try:
			pha2=int(pha2)
			if pha2>0 and pha2<=len(lst):
				pha2=pha2-1
				hserv=lst[pha2]
				return hserv;
			print Col["red"],"Invalid!",Col["0"]

		except:
			print Col["red"],"Invalid!",Col["0"]	
			pha2=0


#
################ START ########################
#

try:
	os.system("stty echo")
	os.system(conf_clawsexit)
	print "\033[2J\033[0;0H\n"
	print Col["blue"]+" onion"+Col["green"]+".py "+Col["purple"]+"TAILS client setup"+Col["green"]+" Ver "+conf_version+Col["0"]
	print "\t"+Col["blue"]+"(C) 2014 OnionMail.info & "+Col["cyan"]+"Tramaci.org"+Col["0"]
	print "\n"+Col["cyan"]+"This program will subscribe/configure your OnionMail on Claws-Mail client."+Col["0"]
	print Col["purple"]+"Do wou want to automatically configure your onion/mailbox now?"+Col["0"]
	print "\t"+Col["purple"]+"(Y)"+Col["0"],"=",Col["cyan"]+"Yes"+Col["0"]
	print "\t"+Col["purple"]+"(N)"+Col["0"],"=",Col["cyan"]+"No"+Col["0"]

	while 1:
		print Col["purple"]+"\t>"+Col["0"],
		pha2 = sys.stdin.readline()
		print ""
		pha2 = string.strip(pha2)
		pha2 = string.lower(pha2)
		if pha2=="y":
			break

		if pha2=="n":
			print "\033[2J\033[0;0H\n"
			print Col["green"]+"Ok, Goodbye"+Col["0"],"\n"
			sys.exit(0)

	print "\033[2J\033[0;0H\n"
	print Col["cyan"],"\nRunning setup wizard:\n",Col["0"]

	print Col["cyan"],"Importing my PGP key...",Col["0"]
	importmypgp()
	print "\t",Col["blue"],"Done!!!",Col["0"]

	cwd = os.getcwd();
	if cwd.find("/home/")!=0:
		print Col["cyan"],"Loading configuration...",Col["0"]
		if not os.path.isdir(conf_tempath):
			os.makedirs(conf_tempath)
		for inf in [ conf_tarprofile , conf_tarmail ]:
			if os.path.isfile(inf):
				os.system("cp "+inf+" "+conf_tempath+"/"+inf)
		os.chdir(conf_tempath)
		print "\t",Col["blue"],"Done!!!",Col["0"]

	print "\n",Col["cyan"],"Download OnionMail servers'status list...",Col["0"]
	download(conf_list)
	print "\t",Col["blue"],"Done!!!",Col["0"]

	print Col["cyan"],"Checking important files...",Col["0"]
	for inf in [ conf_tarprofile , conf_tarmail ]:
		if not os.path.isfile(inf):
			print "\t",Col["purple"],"Download ",inf," ...",Col["0"],
			download(inf)
			print "\t\t",Col["blue"]," Done!!!",Col["0"]
	print "\t",Col["blue"],"Done!!!",Col["0"]

	if not os.path.isfile(conf_tarprofile) or not os.path.isfile(conf_tarmail) or not os.path.isfile(conf_list):
	    ferro("There is a lack of important files. Maybe you lost some part of the program.")

	print Col["cyan"],"Ok\n\tReady to go..."+Col["purple"]+"\tBegin configuration wizard.\n"+Col["0"]

	### parsetor()
	inittheclaws()
	while 1:
		srv = serverlist()
		try:
			print "\033[2J\033[0;0H"+Col["cyan"]+"Connecting to "+Col["green"]+srv["nick"]+Col["0"]+"\n"
			onionmail(srv["onion"])
			os.chdir(startpath)
			break

		except PException:
			print Col["red"] + "Error occurred on "+Col["yellow"]+srv["nick"]+Col["red"]+" server"
			print Col["purple"] + "Press return to try another server."+Col["0"]
			pha2 = sys.stdin.readline()
			os.system("stty echo")

		except KeyboardInterrupt:
			print Col["ored"] + " Interrupted by user "+Col["0"]
			print Col["red"] + "Some operations maybe incomplete!"+Col["0"]
			print "\nServer operations interrupted."
			print "Press return to back server list, Press CTRL+C to end wizard\n"
			pha2 = sys.stdin.readline()
			os.system("stty echo")
			
		except:
			print Col["red"] + "Error occurred in application"
			print Col["purple"] + "Press return to try another server."+Col["0"]
			pha2 = sys.stdin.readline()
			os.system("stty echo")

except KeyboardInterrupt:
	print Col["ored"] + " Interrupted by user "+Col["0"]
	print Col["red"] + "Some operations maybe incomplete!"+Col["0"]
	print "\nWizard aborted.\n"
	os.system("stty echo")
	print Col["purple"] + "Press return to exit."+Col["0"]
	pha2 = sys.stdin.readline()
	os.chdir(startpath)
	sys.exit(1)

except:
	print Col["ored"] + "Application fatal error!"+Col["0"]
	print Col["red"] + "Some operations maybe incomplete!"+Col["0"]
	print "\nWizard aborted.\n"
	os.system("stty echo")
	print Col["purple"] + "Press return to exit."+Col["0"]
	pha2 = sys.stdin.readline()
	os.chdir(startpath)
	sys.exit(1)
		

