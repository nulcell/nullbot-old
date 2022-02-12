#!/bin/bash

: 'Set the main variables'
YELLOW="\033[1;33m"
GREEN="\033[0;32m"
RESET="\033[0m"
domain="$1"
BASE="$HOME/tools"
GOBIN="$HOME/go/bin"

RESULTDIR="$BASE/nullbot/output/$domain"
SCREENSHOTS="$RESULTDIR/screenshots"
SUBS="$RESULTDIR/subdomains"
GFSCAN="$RESULTDIR/gfscan"
IPS="$RESULTDIR/ips"
PORTSCAN="$RESULTDIR/portscan"
ARCHIVE="$RESULTDIR/archive"
NUCLEISCAN="$RESULTDIR/nucleiscan"
DIRSEARCH="$RESULTDIR/discovery"
SPIDER="$RESULTDIR/spider"
TECH="$RESULTDIR/tech"

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
}

: 'Gather resolvers'
gatherResolvers(){
	notify "Downloading fresh resolvers"
	mkdir -p "$IPS"
	wget -q https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O "$IPS"/resolvers.txt
}

: 'subdomain gathering'
gatherSubdomains(){
	notify "Getting subdomains"
	mkdir -p "$SUBS"

	notify "Starting assetfinder"
	"$GOBIN"/assetfinder --subs-only "$domain" >"$SUBS"/assetfinder.txt
	notify "Done, next."

	notify "Starting subfinder"
	"$GOBIN"/subfinder -silent -d "$domain" -all -config "$BASE"/nullbot/modules/recon/configs/config.yaml -o "$SUBS"/subfinder.txt 1>/dev/null 2>/dev/null
	notify "Done, next."

	notify "Starting amass"
	#"$GOBIN"/amass enum -silent -d "$domain" -config "$BASE"/nullbot/modules/recon/configs/config.ini -o "$SUBS"/amass.txt | "$GOBIN"/anew -q "$SUBS"/amass-anew.txt &
	#pid=$!
	#echo "waiting 20 minutes for amass"
	#sleep 1200
	#kill $pid

	# testing
	"$GOBIN"/amass enum -silent -active -brute -d "$domain" -config "$BASE"/nullbot/modules/recon/configs/config.ini -o "$SUBS"/amass.txt
	notify "Done, next."

	# Add altdns to expand scope of subdomain search

	notify "Combining and sorting results.."
	cat "$SUBS"/*.txt | sort -u | "$GOBIN"/anew -q "$SUBS"/subdomains

	notify "Resolving subdomains.."
	cat "$SUBS"/subdomains | sort -u | "$GOBIN"/shuffledns -silent -d "$domain" -r "$IPS"/resolvers.txt > "$SUBS"/alive_subdomains.txt
	
	notify "Getting alive hosts.."
	cat "$SUBS"/alive_subdomains.txt | "$GOBIN"/httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 50 | "$GOBIN"/anew -q "$SUBS"/hosts.txt
	notify "Done."
}

techDiscovery(){
	notify "Checking web technologies"
	mkdir -p $TECH
	whatweb -i "$SUBS"/hosts.txt -H "x-bug-bounty: $hackerhandle" -a 3 --log-brief="$TECH"/log.txt --log-verbose="$TECH"/log-verbose.txt --log-xml=log.xml --no-errors -q 2>/dev/null
	cat "$TECH"/log.txt | grep "200 OK" > "$TECH"/technologies.txt
	notify "Done."
}

: 'subdomain takeover check'
checkTakeovers(){
	notify "Checking for subdomain takeover"

	notify "Starting subjack"
	"$GOBIN"/subjack -w "$SUBS"/subdomains -a -t 50 -v -c "$HOME"/go/src/github.com/haccer/subjack/fingerprints.json -o "$SUBS"/all-takeover-checks.txt -ssl 2>/dev/null 1>/dev/null
	grep -v "Not Vulnerable" "$SUBS"/all-takeover-checks.txt > "$SUBS"/takeovers
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
	"$GOBIN"/nuclei -silent -l "$SUBS"/subdomains -t "$HOME"/nuclei-templates/takeovers -c 50 -o "$SUBS"/nuclei-takeover.txt 2>/dev/null 1>/dev/null
	vulnto=$(cat "$SUBS"/nuclei-takeover.txt)
	if [[ $vulnto != "" ]]; then
		notify "Possible subdomain takeovers:"
		for line in "$SUBS"/nuclei-takeover.txt; do
			notify "--> $vulnto "
		done
	else
		notify "No takeovers found."
	fi
	notify "Done."
}

: 'Get all CNAME'
getCNAME(){
	notify "Getting CNAMEs"
	"$GOBIN"/dnsprobe -silent -r CNAME -l "$SUBS"/subdomains -o "$SUBS"/subdomains_cname.txt
	notify "Done."
}

: 'Gather IPs with dnsprobe'
gatherIPs(){
	notify "Gathering IPs"
	mkdir -p "$IPS"
	"$GOBIN"/dnsprobe -l "$SUBS"/subdomains -silent -f ip | sort -u | "$GOBIN"/anew -q "$IPS"/"$domain"-ips.txt
	notify "Done."
}

fetchArchive(){
	notify "Fetching Archives"
	mkdir -p "$ARCHIVE"
	cat "$SUBS"/alive_subdomains.txt | "$GOBIN"/gau | sort | uniq -u > "$ARCHIVE"/urls.txt
	cat "$ARCHIVE"/urls.txt  | sort -u | "$GOBIN"/unfurl --unique keys > "$ARCHIVE"/paramlist.txt
	notify "Pulling extensions from archive"
	cat "$ARCHIVE"/urls.txt  | sort -u | grep -P "\w+\.txt(\?|$)" | "$GOBIN"/httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/text.txt
	cat "$ARCHIVE"/urls.txt  | sort -u | grep -P "\w+\.bak(\?|$)" | "$GOBIN"/httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/bak.txt
	cat "$ARCHIVE"/urls.txt  | sort -u | grep -P "\w+\.js(\?|$)" | "$GOBIN"/httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/jsurls.txt
	cat "$ARCHIVE"/urls.txt  | sort -u | grep -P "\w+\.php(\?|$)" | "$GOBIN"/httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/phpurls.txt
	cat "$ARCHIVE"/urls.txt  | sort -u | grep -P "\w+\.aspx(\?|$)" | "$GOBIN"/httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/aspxurls.txt
	cat "$ARCHIVE"/urls.txt  | sort -u | grep -P "\w+\.jsp(\?|$)" | "$GOBIN"/httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/jspurls.txt
	notify "Done."
}

fetchEndpoints(){
	notify "Fetching endpoints"
	mkdir -p "$ARCHIVE"/endpoints/
	
	for js in `cat "$ARCHIVE"/jsurls.txt`;
	do
		file=`echo "$js" | cut -d "/" -f 3`
		python3 "$HOME"/tools/LinkFinder/linkfinder.py -i $js -o cli | "$GOBIN"/anew -q "$ARCHIVE"/endpoints/"$file".txt;
	done
	notify "Done."
}

: 'Use gf to find secrets in responses'
startGfScan(){
	notify "Basic vuln check with gf"
	mkdir -p "$GFSCAN"
	cd "$ARCHIVE"
	for i in `gf -list`; do "$GOBIN"/gf ${i} urls.txt | "$GOBIN"/anew -q "$GFSCAN"/"${i}".txt; done
	cd ~
	notify "Done."
}

: 'Gather screenshots'
gatherScreenshots(){
	notify "Taking screenshots"
	mkdir -p "$SCREENSHOTS"
	cat "$SUBS"/hosts.txt | aquatone -silent -http-timeout 10000 -ports xlarge -out "$SCREENSHOTS" 2>/dev/null 1>/dev/null
	notify "Done."
}

: 'Check for Vulnerabilities'
runNuclei(){
	notify  "Nuclei Defaults Scan"
	mkdir -p "$NUCLEISCAN"
	"$GOBIN"/nuclei -l "$SUBS"/hosts.txt -c 100 -rl 100 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/info.txt -severity info -silent > /dev/null
	sleep 10
	"$GOBIN"/nuclei -l "$SUBS"/hosts.txt -c 100 -rl 100 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/vulns.txt -severity low,medium,high,critical -silent > /dev/null
	notify "Done."
}

runSpider(){
	notify "Crawling sites"
	mkdir -p $SPIDER
	# "$GOBIN"/gospider -S "$SUBS"/hosts.txt -u $hackerhandle -a -r -t 5 -c 10 -o $SPIDER > /dev/null
	"$GOBIN"/gospider -s https://"$domain" -u $hackerhandle -a -r -t 5 -c 10 -o $SPIDER > /dev/null
	notify "Done."
}

runSearch(){
	notify "Checking for directories and hidden files"
	mkdir -p $DIRSEARCH
	sleep 5
	
	# Using interlace and ffuf
	# interlace -tL "$SUBS"/hosts.txt -threads 5 --silent -c ""$GOBIN"/ffuf -u _target_/FUZZ -w "$BASE"/nullbot/modules/recon/wordlists/fuzz.txt -fc 404,400,500 -or -o ffuftest.txt -v 2>/dev/null | grep URL | cut -d '|' -f 3 | "$GOBIN"/anew -q "$DIRSEARCH"/interlace.txt"

	# slower alternative
	#python3 ~/tools/dirsearch/dirsearch.py -u "$domain" -w "$BASE"/nullbot/modules/recon/wordlists/fuzz.txt -F --full-url --no-color --quiet --scheme=https | "$GOBIN"/anew -q "$DIRSEARCH"/basic.txt
	#"$GOBIN"/ffuf -u https://"$domain"/FUZZ -w "$BASE"/nullbot/modules/recon/wordlists/fuzz.txt -fc 404,400,500 -or -o ffuftest.txt -v 2>/dev/null | grep URL | cut -d '|' -f 3 | "$GOBIN"/anew -q "$DIRSEARCH"/result.txt
	"$GOBIN"/ffuf -u https://"$domain"/FUZZ -w "$BASE"/nullbot/modules/recon/wordlists/fuzz.txt -fc 404,400,500 -v 2>/dev/null | "$GOBIN"/anew -q "$DIRSEARCH"/result.txt

	#notify "Combining results.."
	#cat "$DIRSEARCH"/*.txt | cut -d "-" -f 3 | "$GOBIN"/anew -q "$DIRSEARCH"/result.txt

	#notify "Running nuclei on discovered points"
	#"$GOBIN"/nuclei -l "$DIRSEARCH"/result.txt -c 100 -rl 100 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/dir-info.txt -severity info -silent 2>/dev/null 1>/dev/null
	#"$GOBIN"/nuclei -l "$DIRSEARCH"/result.txt -c 500 -rl 500 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/dir-vulns.txt -severity low,medium,high,critical -silent 2>/dev/null 1>/dev/null
	notify "Done."
}

: 'Portscan on found IP addresses'
portScan(){
	notify "Running Port Scan"
	mkdir -p "$PORTSCAN"
	nmap -sV -T4 --max-retries 10 -p- --script vulners,http-title --min-rate 100000 -iL "$SUBS"/alive_subdomains.txt -oA "$PORTSCAN"/recon-hosts.txt 2>/dev/null 1>/dev/null
	nmap -sV -T4 --max-retries 10 -p- --script vulners,http-title --min-rate 100000 -iL "$IPS"/"$domain"-ips.txt -oA "$PORTSCAN"/recon-ips 2>/dev/null 1>/dev/null
	notify "Done."
}

notifySlack(){
	notify "Triggering Slack Notification"

	echo -e "NullBot recon on $domain completed!" | "$GOBIN"/slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	totalsum=$(cat $SUBS/hosts.txt | wc -l)
	echo -e "$totalsum live subdomain hosts.txt discovered" | "$GOBIN"/slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null

	possibletko="$(cat $SUBS/takeovers | wc -l)"
	if [ -s "$SUBS/takeovers" ]; then
        	echo -e "Found $possibletko possible subdomain takeovers." | "$GOBIN"/slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	else
        	echo "No subdomain takeovers found." | "$GOBIN"/slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	fi

	if [ -f "$NUCLEISCAN/vulns.txt" ]; then
		echo "exploits discovered:" | "$GOBIN"/slackcat 2>/dev/null 1>/dev/null
		cat "$NUCLEISCAN/vulns.txt" | "$GOBIN"/slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	else
		echo -e "No exploits discovered." | "$GOBIN"/slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	fi

	notify "Done."
}

: "Handle Ctrl-c"
function trap_ctrlc ()
{
    # perform cleanup here
    echo "Ctrl-C caught...performing clean up"

    echo "Doing cleanup"

    # exit shell script with error code 2
    # if omitted, shell script will continue execution
    exit 2
}

: 'Execute the main functions'

# initialise trap to call trap_ctrlc function
# when signal 2 (SIGINT) is received
trap "trap_ctrlc" 2

source ${BASE}/nullbot/modules/recon/configs/tokens

checkArguments
checkDirectories
gatherResolvers
gatherSubdomains
techDiscovery
getCNAME
gatherIPs
checkTakeovers
fetchArchive
fetchEndpoints
startGfScan
gatherScreenshots
runSearch
runNuclei
runSpider
# portScan # (add an if statement to control the running)
notifySlack
