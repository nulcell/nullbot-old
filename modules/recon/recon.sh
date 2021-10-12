#!/bin/bash

: 'Set the main variables'
YELLOW="\033[1;33m"
GREEN="\033[0;32m"
RESET="\033[0m"
domain="$1"
RESULTDIR="$HOME/assets/$domain"
SCREENSHOTS="$RESULTDIR/screenshots"
SUBS="$RESULTDIR/subdomains"
GFSCAN="$RESULTDIR/gfscan"
IPS="$RESULTDIR/ips"
PORTSCAN="$RESULTDIR/portscan"
ARCHIVE="$RESULTDIR/archive"
NUCLEISCAN="$RESULTDIR/nucleiscan"

startFunction() {
	tool=$1
	echo -e "[$GREEN+$RESET] Starting $tool"
}

: 'Display help text when no arguments are given'
checkArguments() {
	if [[ -z $domain ]]; then
		echo -e "[$GREEN+$RESET] Usage: recon <domain.tld>"
		exit 1
	fi
}

checkDirectories() {
	echo -e "[$GREEN+$RESET] Creating directories and grabbing wordlists for $GREEN$domain$RESET.."
	mkdir -p "$RESULTDIR"
	mkdir -p "$SUBS" "$SCREENSHOTS" "$IPS" "$PORTSCAN" "$ARCHIVE" "$NUCLEISCAN" "$GFSCAN"
}

: 'Gather resolvers'
gatherResolvers() {
	startFunction "Downloading fresh resolvers"
	wget -q https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O "$IPS"/resolvers.txt
}

: 'subdomain gathering'
gatherSubdomains() {
	startFunction "sublert"
	echo -e "[$GREEN+$RESET] Checking for existing sublert output, otherwise add it."
	if [ ! -e "$SUBS"/sublert.txt ]; then
		cd "$HOME"/tools/sublert || return
		python3 sublert.py -q False -u "$domain" 2>/dev/null 1>/dev/null
		cp "$HOME"/tools/sublert/output/"$domain".txt "$SUBS"/sublert.txt
		cd "$HOME" || return
	else
		cp "$HOME"/tools/sublert/output/"$domain".txt "$SUBS"/sublert.txt
	fi
	echo -e "[$GREEN+$RESET] Done, next."

	startFunction "subfinder"
	"$HOME"/go/bin/subfinder -silent -d "$domain" -all -config "$HOME"/nullbot/modules/recon/configs/config.yaml -o "$SUBS"/subfinder.txt 1>/dev/null 2>/dev/null
	echo -e "[$GREEN+$RESET] Done, next."

	startFunction "assetfinder"
	"$HOME"/go/bin/assetfinder --subs-only "$domain" >"$SUBS"/assetfinder.txt
	echo -e "[$GREEN+$RESET] Done, next."

	startFunction "amass"
	"$HOME"/go/bin/amass enum -silent -passive -d "$domain" -config "$HOME"/nullbot/modules/recon/configs/config.ini -o "$SUBS"/amassp.txt
	echo -e "[$GREEN+$RESET] Done, next."

	startFunction "findomain"
	findomain -q -t "$domain" -u "$SUBS"/findomain_subdomains.txt 2>/dev/null 1>/dev/null
	echo -e "[$GREEN+$RESET] Done, next."

	startFunction "rapiddns"
	crobat -s "$domain" | sort -u | anew -q "$SUBS"/rapiddns_subdomains.txt
	echo -e "[$GREEN+$RESET] Done, next."

	echo -e "[$GREEN+$RESET] Combining and sorting results.."
	cat "$SUBS"/*.txt | sort -u >"$SUBS"/subdomains
	echo -e "[$GREEN+$RESET] Resolving subdomains.."
	cat "$SUBS"/subdomains | sort -u | shuffledns -silent -d "$domain" -r "$IPS"/resolvers.txt > "$SUBS"/alive_subdomains
	echo -e "[$GREEN+$RESET] Getting alive hosts.."
	#httpx -l "$SUBS"/subdomains -silent -threads 9000 -timeout 30 | anew -q "$SUBS"/hosts_httpx
	cat "$SUBS"/alive_subdomains | httprobe | anew -q "$SUBS"/hosts
	echo -e "[$GREEN+$RESET] Done."
}

: 'subdomain takeover check'
checkTakeovers() {
	startFunction "subjack"
	"$HOME"/go/bin/subjack -w "$SUBS"/hosts -a -t 50 -v -c "$HOME"/go/src/github.com/haccer/subjack/fingerprints.json -o "$SUBS"/all-takeover-checks.txt -ssl 2>/dev/null 1>/dev/null
	grep -v "Not Vulnerable" <"$SUBS"/all-takeover-checks.txt >"$SUBS"/takeovers
	rm "$SUBS"/all-takeover-checks.txt

	vulnto=$(cat "$SUBS"/takeovers)
	if [[ $vulnto == *i* ]]; then
		echo -e "[$GREEN+$RESET] Possible subdomain takeovers:"
		for line in "$SUBS"/takeovers; do
			echo -e "[$GREEN+$RESET] --> $vulnto "
		done
	else
		echo -e "[$GREEN+$RESET] No takeovers found."
	fi

	startFunction "nuclei subdomain takeover check"
	nuclei -silent -l "$SUBS"/hosts -t "$HOME"/nuclei-templates/takeovers -c 50 -o "$SUBS"/nuclei-takeover-checks.txt 2>/dev/null 1>/dev/null
	vulnto=$(cat "$SUBS"/nuclei-takeover-checks.txt)
	if [[ $vulnto != "" ]]; then
		echo -e "[$GREEN+$RESET] Possible subdomain takeovers:"
		for line in "$SUBS"/nuclei-takeover-checks.txt; do
			echo -e "[$GREEN+$RESET] --> $vulnto "
		done
	else
		echo -e "[$GREEN+$RESET] No takeovers found."
	fi
}

: 'Get all CNAME'
getCNAME() {
	startFunction "dnsprobe to get CNAMEs"
	dnsprobe -silent -r CNAME -l "$SUBS"/subdomains -o "$SUBS"/subdomains_cname.txt
}

: 'Gather IPs with dnsprobe'
gatherIPs() {
	startFunction "dnsprobe"
	dnsprobe -l "$SUBS"/subdomains -silent -f ip | sort -u | anew -q "$IPS"/"$domain"-ips.txt
	python3 $HOME/nullbot/modules/recon/scripts/clean_ips.py "$IPS"/"$domain"-ips.txt "$IPS"/"$domain"-origin-ips.txt
	echo -e "[$GREEN+$RESET] Done."
}

: 'Portscan on found IP addresses'
portScan() {
	startFunction  "Port Scan"
	nmap -sV -T4 --max-retries 2 -p- --script vulners,http-title --min-rate 100000 -iL "$SUBS"/alive_subdomains -oA "$PORTSCAN"/recon-hosts 2>/dev/null 1>/dev/null
	#nmap -sV -T4 --max-retries 2 -p- --script vulners,http-title --min-rate 100000 -iL "$IPS"/"$domain"-ips.txt -oA "$PORTSCAN"/recon-ips 2>/dev/null 1>/dev/null
	echo -e "[$GREEN+$RESET] Port Scan finished"
}

: 'Gather screenshots'
gatherScreenshots() {
	startFunction "Screenshot Gathering"
	cat "$SUBS"/hosts | aquatone -silent -http-timeout 10000 -ports xlarge -out "$SCREENSHOTS" 2>/dev/null 1>/dev/null
	echo -e "[$GREEN+$RESET] Screenshot Gathering finished"
}

fetchArchive() {
	startFunction "fetchArchive"
	cat "$SUBS"/hosts | sed 's/https\?:\/\///' | gau > "$ARCHIVE"/getallurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | unfurl --unique keys > "$ARCHIVE"/paramlist.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.js(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/jsurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.php(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/phpurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.aspx(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/aspxurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.jsp(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/jspurls.txt
	echo -e "[$GREEN+$RESET] fetchArchive finished"
}

fetchEndpoints() {
	startFunction "fetchEndpoints"
	for js in `cat "$ARCHIVE"/jsurls.txt`;
	do
		python3 "$HOME"/tools/LinkFinder/linkfinder.py -i $js -o cli | anew -q "$ARCHIVE"/endpoints.txt;
	done
	echo -e "[$GREEN+$RESET] fetchEndpoints finished"
}

: 'Use gf to find secrets in responses'
startGfScan() {
	startFunction "Checking for vulnerabilites using gf"
	cd "$ARCHIVE"
	for i in `gf -list`; do gf ${i} getallurls.txt | anew -q "$GFSCAN"/"${i}".txt; done
	cd ~
}

: 'Check for Vulnerabilities'
runNuclei() {
	startFunction  "Nuclei Defaults Scan"
	nuclei -l "$SUBS"/hosts -c 100 -rl 200 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/default-info.txt -severity info -silent 2>/dev/null 1>/dev/null
	nuclei -l "$SUBS"/hosts -c 100 -rl 200 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/default-vulns.txt -severity low,medium,high,critical -silent 2>/dev/null 1>/dev/null
	echo -e "[$GREEN+$RESET] Nuclei Scan finished"
}

notifySlack() {
	startFunction "Trigger Slack Notification"

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
		echo "exploits discovered:" | slackcat
		cat "$NUCLEISCAN/default-vulns.txt" | slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	else
		echo -e "No exploits discovered." | slackcat -u $SLACK_WEBHOOK_URL 2>/dev/null 1>/dev/null
	fi

	echo -e "[$GREEN+$RESET] Done."
}

notifyDiscord() {
	startFunction "Trigger Discord Notification"
	intfiles=$(cat $NUCLEISCAN/*.txt | wc -l)

	totalsum=$(cat $SUBS/hosts | wc -l)
	message="**$domain scan completed!\n $totalsum live hosts discovered.**\n"

	if [ -s "$SUBS/takeovers" ]
	then
			posibbletko="$(cat $SUBS/takeovers | wc -l)"
			message+="**Found $posibbletko possible subdomain takeovers.**\n"
	else
			message+="**No subdomain takovers found.**\n"
	fi

	cd $NUCLEISCAN
	for file in *.txt
	do
		if [ -s "$file" ]
		then
			fileName=$(basename ${file%%.*})
			fileNameUpper="$(tr '[:lower:]' '[:upper:]' <<< ${fileName:0:1})${fileName:1}"
			nucleiData="$(jq -Rs . <$file | cut -c 2- | rev | cut -c 2- | rev)"
			message+="**$fileNameUpper discovered:**\n "$nucleiData"\n"
		fi
	done

	python3 $HOME/nullbot/modules/recon/scripts/webhook_Discord.py <<< $(echo "$message")

	echo -e "[$GREEN+$RESET] Done."
}

: 'Execute the main functions'

source "$HOME"/nullbot/modules/recon/configs/tokens

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
#notifyDiscord
