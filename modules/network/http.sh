#!/bin/bash

: 'http services directories'
HTTP="$RESULTDIR/http"
AQUATONE="$HTTP/aquatone"
NUCLEISCAN="$HTTP/nucleiscan"
DIRSEARCH="$HTTP/dirsearch"
CMS="$HTTP/cms"

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
	nuclei -target http://${ADDRESS} -o "$NUCLEISCAN"/default-info.txt -severity info -silent 2>/dev/null 1>/dev/null
	nuclei -target http://${ADDRESS} -o "$NUCLEISCAN"/default-vulns.txt -severity low,medium,high,critical -silent 2>/dev/null 1>/dev/null
	notify "Nuclei Scan finished"
}

runDirecoryScanner(){
	notify "Starting Directory Bruteforce"
	if [ -e /usr/share/seclists ]; then
		mkdir -p $DIRSEARCH
		dirsearch -q --url http://$ADDRESS/ --wordlists /usr/share/seclists/Discovery/Web-Content/SVNDigger/all.txt -t 50 --output "$DIRSEARCH/raft-dir.txt" 2>/dev/null 1>/dev/null
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
			wpscan --url http://${ADDRESS} --enumerate --api-token `cat $HOME/wpscan-api` --output "$CMS/wpscan.txt"
		else
			wpscan --url http://${ADDRESS} --output "$CMS/wpscan.txt"
		fi
	else
		alert "No CMS found"
	fi
	notify "CMS Scanner finished"
}

scanHTTP(){
    mkdir -p $HTTP
	runAquatone
	runNuclei
	sleep 2
	runCMSScanner
	sleep 2
	runDirecoryScanner
}