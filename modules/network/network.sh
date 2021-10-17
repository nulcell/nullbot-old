#!/bin/bash

YELLOW="\033[0;33m"
RED="\033[0;31m"
GREEN="\033[0;32m"
RESET="\033[0m"
ADDRESS="$1"

: 'base directories'
RESULTDIR="$HOME/nullbot/output/$ADDRESS"
PORTSCAN="$RESULTDIR/portscan"

: 'http services directories'
HTTP="$HTTP/http"
AQUATONE="$HTTP/aquatone"
NUCLEISCAN="$HTTP/nucleiscan"
DIRSEARCH="$HTTP/dirsearch"
CMS="$HTTP/cms"

notify(){
	echo -e "$GREEN[+]$RESET $1"
}

alert(){
	echo -e "${YELLOW}[i]${RESET} $1"
}

error(){
	echo -e "${RED}[x]${RESET} $1"
}

checkArguments(){
	if [[ -z $ADDRESS ]]; then
		error "Usage: ctf.sh <IP>"
		exit 1
	fi
}

checkDirectories(){
	notify "Creating directory for $GREEN$ADDRESS$RESET.."
	mkdir -p $RESULTDIR
	mkdir -p $PORTSCAN $HTTP
}

: 'Core Functions'
runPortScan(){
	notify "Starting Nmap scan"
	nmap -sV -T4 --max-retries 2 --min-rate 10000 -oA "$PORTSCAN"/fast $ADDRESS 2>/dev/null 1>/dev/null
	nmap -sV -T4 --max-retries 2 --min-rate 10000 -sC -p- --script vulners -oA "$PORTSCAN"/full $ADDRESS 2>/dev/null 1>/dev/null
	notify "Nmap scan finished"
}


: 'HTTP services functions'
runAquatone(){
	notify "Starting Aquatone"
	mkdir -p  $AQUATONE
	cat "$PORTSCAN"/full.xml | aquatone -silent -http-timeout 10000 -nmap -ports xlarge -out "$AQUATONE" 2>/dev/null 1>/dev/null
	notify "Aquatone scan finished"
}

runNuclei(){
	notify "Starting Nuclei Default Scan"
	mkdir -p $NUCLEISCAN
	nuclei -target $ADDRESS -o "$NUCLEISCAN"/default-info.txt -severity info -silent 2>/dev/null 1>/dev/null
	nuclei -target $ADDRESS -o "$NUCLEISCAN"/default-vulns.txt -severity low,medium,high,critical -silent 2>/dev/null 1>/dev/null
	notify "Nuclei Scan finished"
}

runDirecoryScanner(){
	notify "Starting Directory Bruteforce"
	if [ -e /usr/share/seclists ]; then
		mkdir -p $DIRSEARCH
		dirsearch -q --url http://$ADDRESS/ --wordlists /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt --output "$DIRSEARCH/raft-dir.txt" 2>/dev/null 1>/dev/null
	fi
	notify "Directory Bruteforce finished"
}

runCMSScanner(){
	notify "Starting CMS Scanner"
	CMSCHECK=`whatweb ${ADDRESS} | grep -o WordPress | head -n 1`
	if [ $CMSCHECK == 'WordPress' ]; then
		alert "Found WordPress"
		notify "Running wpscan on site"
		mkdir -p $CMS
		if [ -e $HOME/wpscan-api ] && [ -e /usr/share/seclists ]; then
			wpscan --url http://${ADDRESS} --enumerate --plugins-detection aggressive --passwords /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt --api-token `cat $HOME/wpscan-api` --output "$CMS/wpscan.txt"
		else
			wpscan --url http://${ADDRESS} --output "$CMS/wpscan.txt"
		fi
	else
		alert "No CMS found"
	fi
	notify "CMS Scanner finished"
}

scanHTTP(){
	runAquatone
	runNuclei
	runCMSScanner
	runDirecoryScanner
}

: 'Main'
checkArguments
checkDirectories
runPortScan
scanHTTP
