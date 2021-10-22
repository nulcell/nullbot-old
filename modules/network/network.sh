#!/bin/bash

YELLOW="\033[0;33m"
RED="\033[0;31m"
GREEN="\033[0;32m"
RESET="\033[0m"
ADDRESS="$1"

: 'base directories'
NULLBOTDIR="$HOME/tools/nullbot"
RESULTDIR="$NULLBOTDIR/output/$ADDRESS"
PORTSCAN="$RESULTDIR/portscan"

: 'modules'
HTTPMODULE="$NULLBOTDIR/modules/network/http.sh"

source $HTTPMODULE

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
	mkdir -p $PORTSCAN
}

: 'Core Functions'
runPortScan(){
	notify "Starting Nmap scan"
	nmap --max-retries 10 -T4 --min-rate 10000 -p- -oA "$PORTSCAN"/ports $ADDRESS 2>/dev/null 1>/dev/null
	openPorts=`grep -v '><state state="closed"' ${PORTSCAN}/ports.xml | xmlstarlet sel -t -v '//port[@protocol="tcp"]/@portid' | xargs echo -n | tr " " ","`
	alert "Ports $openPorts are open"

	sleep 5
	nmap -p $openPorts -sV -T4 -A --script vulners -oA "$PORTSCAN"/full $ADDRESS 2>/dev/null 1>/dev/null
	notify "Nmap scan finished"
}

: 'Main'
checkArguments
checkDirectories
runPortScan
scanHTTP
