#!/bin/bash

: 'Set the main variables'
YELLOW="\033[1;33m"
GREEN="\033[0;32m"
RESET="\033[0m"
domain="$1"
RESULTDIR="$HOME/tools/nullbot/output/$domain"
SCREENSHOTS="$RESULTDIR/screenshots"
SUBS="$RESULTDIR/subdomains"
GFSCAN="$RESULTDIR/gfscan"
IPS="$RESULTDIR/ips"
PORTSCAN="$RESULTDIR/portscan"
ARCHIVE="$RESULTDIR/archive"
NUCLEISCAN="$RESULTDIR/nucleiscan"

notify(){
	echo -e "$GREEN[+]$RESET $1"
}

: 'Display help text when no arguments are given'
checkArguments(){
	if [[ -z $domain ]]; then
		notify "Usage: recon <domain.tld>"
		exit 1
	fi
}

checkDirectories(){
	notify "Creating directories and grabbing wordlists for $GREEN$domain$RESET.."
	mkdir -p "$RESULTDIR"
	mkdir -p "$SUBS" "$SCREENSHOTS" "$IPS" "$PORTSCAN" "$ARCHIVE" "$NUCLEISCAN" "$GFSCAN"
}

: 'Gather resolvers'
gatherResolvers(){
	notify "Starting Downloading fresh resolvers"
	wget -q https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O "$IPS"/resolvers.txt
}

: 'subdomain gathering'
gatherSubdomains(){
	notify "Starting sublert"
	notify "Checking for existing sublert output, otherwise add it."
	if [ ! -e "$SUBS"/sublert.txt ]; then
		cd "$HOME"/tools/sublert || return
		python3 sublert.py -q False -u "$domain" 2>/dev/null 1>/dev/null
		cp "$HOME"/tools/sublert/output/"$domain".txt "$SUBS"/sublert.txt
		cd "$HOME" || return
	else
		cp "$HOME"/tools/sublert/output/"$domain".txt "$SUBS"/sublert.txt
	fi
	notify "Done, next."

	notify "Starting subfinder"
	"$HOME"/go/bin/subfinder -silent -d "$domain" -all -config "$HOME"/nullbot/modules/recon/configs/config.yaml -o "$SUBS"/subfinder.txt 1>/dev/null 2>/dev/null
	notify "Done, next."

	notify "Starting assetfinder"
	"$HOME"/go/bin/assetfinder --subs-only "$domain" >"$SUBS"/assetfinder.txt
	notify "Done, next."

	notify "Starting amass"
	"$HOME"/go/bin/amass enum -silent -passive -d "$domain" -config "$HOME"/nullbot/modules/recon/configs/config.ini -o "$SUBS"/amassp.txt
	notify "Done, next."

	notify "Starting findomain"
	findomain -q -t "$domain" -u "$SUBS"/findomain_subdomains.txt 2>/dev/null 1>/dev/null
	notify "Done, next."

	notify "Starting rapiddns"
	crobat -s "$domain" | sort -u | anew -q "$SUBS"/rapiddns_subdomains.txt
	notify "Done, next."

	notify "Combining and sorting results.."
	cat "$SUBS"/*.txt | sort -u >"$SUBS"/subdomains
	notify "Resolving subdomains.."
	cat "$SUBS"/subdomains | sort -u | shuffledns -silent -d "$domain" -r "$IPS"/resolvers.txt > "$SUBS"/alive_subdomains
	notify "Getting alive hosts.."
	httpx -l "$SUBS"/subdomains -silent -threads 9000 -timeout 30 | anew -q "$SUBS"/hosts
	cat "$SUBS"/alive_subdomains | httprobe | anew -q "$SUBS"/hosts
	notify "Done."
}

: 'subdomain takeover check'
checkTakeovers(){
	notify "Starting subjack"
	"$HOME"/go/bin/subjack -w "$SUBS"/hosts -a -t 50 -v -c "$HOME"/go/src/github.com/haccer/subjack/fingerprints.json -o "$SUBS"/all-takeover-checks.txt -ssl 2>/dev/null 1>/dev/null
	grep -v "Not Vulnerable" <"$SUBS"/all-takeover-checks.txt >"$SUBS"/takeovers
	rm "$SUBS"/all-takeover-checks.txt

	vulnto=$(cat "$SUBS"/takeovers)
	if [[ $vulnto == *i* ]]; then
		notify "Possible subdomain takeovers:"
		for line in "$SUBS"/takeovers; do
			notify "--> $vulnto "
		done
	else
		notify "No takeovers found."
	fi

	notify "Starting nuclei subdomain takeover check"
	nuclei -silent -l "$SUBS"/hosts -t "$HOME"/nuclei-templates/takeovers -c 50 -o "$SUBS"/nuclei-takeover-checks.txt 2>/dev/null 1>/dev/null
	vulnto=$(cat "$SUBS"/nuclei-takeover-checks.txt)
	if [[ $vulnto != "" ]]; then
		notify "Possible subdomain takeovers:"
		for line in "$SUBS"/nuclei-takeover-checks.txt; do
			notify "--> $vulnto "
		done
	else
		notify "No takeovers found."
	fi
}

: 'Get all CNAME'
getCNAME(){
	notify "Starting dnsprobe to get CNAMEs"
	dnsprobe -silent -r CNAME -l "$SUBS"/subdomains -o "$SUBS"/subdomains_cname.txt
}

: 'Gather IPs with dnsprobe'
gatherIPs(){
	notify "Starting dnsprobe"
	dnsprobe -l "$SUBS"/subdomains -silent -f ip | sort -u | anew -q "$IPS"/"$domain"-ips.txt
	python3 $HOME/nullbot/modules/recon/scripts/clean_ips.py "$IPS"/"$domain"-ips.txt "$IPS"/"$domain"-origin-ips.txt
	notify "Done."
}

: 'Portscan on found IP addresses'
portScan(){
	startFunction  "Port Scan"
	nmap -sV -T4 --max-retries 10 -p- --script vulners,http-title --min-rate 100000 -iL "$SUBS"/alive_subdomains -oA "$PORTSCAN"/recon-hosts 2>/dev/null 1>/dev/null
	nmap -sV -T4 --max-retries 10 -p- --script vulners,http-title --min-rate 100000 -iL "$IPS"/"$domain"-ips.txt -oA "$PORTSCAN"/recon-ips 2>/dev/null 1>/dev/null
	notify "Port Scan finished"
}

: 'Gather screenshots'
gatherScreenshots(){
	notify "Starting Screenshot Gathering"
	cat "$SUBS"/hosts | aquatone -silent -http-timeout 10000 -ports xlarge -out "$SCREENSHOTS" 2>/dev/null 1>/dev/null
	notify "Screenshot Gathering finished"
}

fetchArchive(){
	notify "Starting fetchArchive"
	cat "$SUBS"/hosts | sed 's/https\?:\/\///' | gau > "$ARCHIVE"/getallurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | unfurl --unique keys > "$ARCHIVE"/paramlist.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.js(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/jsurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.php(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/phpurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.aspx(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/aspxurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.jsp(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/jspurls.txt
	notify "fetchArchive finished"
}

fetchEndpoints(){
	notify "Starting fetchEndpoints"
	for js in `cat "$ARCHIVE"/jsurls.txt`;
	do
		python3 "$HOME"/tools/LinkFinder/linkfinder.py -i $js -o cli | anew -q "$ARCHIVE"/endpoints.txt;
	done
	notify "fetchEndpoints finished"
}

: 'Use gf to find secrets in responses'
startGfScan(){
	notify "Starting Checking for vulnerabilites using gf"
	cd "$ARCHIVE"
	for i in `gf -list`; do gf ${i} getallurls.txt | anew -q "$GFSCAN"/"${i}".txt; done
	cd ~
}

: 'Check for Vulnerabilities'
runNuclei(){
	startFunction  "Nuclei Defaults Scan"
	nuclei -l "$SUBS"/hosts -c 100 -rl 100 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/default-info.txt -severity info -silent 2>/dev/null 1>/dev/null
	nuclei -l "$SUBS"/hosts -c 100 -rl 100 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/default-vulns.txt -severity low,medium,high,critical -silent 2>/dev/null 1>/dev/null
	notify "Nuclei Scan finished"
}

notifySlack(){
	notify "Starting Trigger Slack Notification"

	echo -e "NullBot recon on $domain completed!" | slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	totalsum=$(cat $SUBS/hosts | wc -l)
	echo -e "$totalsum live subdomain hosts discovered" | slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null

	posibbletko="$(cat $SUBS/takeovers | wc -l)"
	if [ -s "$SUBS/takeovers" ]; then
        	echo -e "Found $posibbletko possible subdomain takeovers." | slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	else
        	echo "No subdomain takeovers found." | slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	fi

	if [ -f "$NUCLEISCAN/default-vulns.txt" ]; then
		echo "exploits discovered:" | slackcat 2>/dev/null 1>/dev/null
		cat "$NUCLEISCAN/default-vulns.txt" | slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	else
		echo -e "No exploits discovered." | slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	fi

	notify "Done."
}

: 'Execute the main functions'

source "$HOME"/tools/nullbot/modules/recon/configs/tokens

checkArguments
checkDirectories
gatherResolvers
gatherSubdomains
checkTakeovers
getCNAME
gatherIPs
fetchArchive
fetchEndpoints
startGfScan
gatherScreenshots
runNuclei
portScan
notifySlack
