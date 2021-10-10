#!/bin/bash

: 'Set the main variables'
YELLOW="\033[1;33m"
GREEN="\033[0;32m"
RESET="\033[0m"
domain="$1"
RESULTDIR="$HOME/assets/$domain"
WORDLIST="$RESULTDIR/wordlists"
SCREENSHOTS="$RESULTDIR/screenshots"
SUBS="$RESULTDIR/subdomains"
DIRSCAN="$RESULTDIR/directories"
GFSCAN="$RESULTDIR/gfscan"
IPS="$RESULTDIR/ips"
PORTSCAN="$RESULTDIR/portscan"
ARCHIVE="$RESULTDIR/archive"
NUCLEISCAN="$RESULTDIR/nucleiscan"
VERSION="0.1"

: 'Display the logo'
startRecon() {
	echo -e "
----------------------------------------
NullBot Recon
v$VERSION - $YELLOW@NullCell8822$RESET

modified form ReconPi - https://github.com/x1mdev/ReconPi
----------------------------------------"
}

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
	mkdir -p "$SUBS" "$SCREENSHOTS" "$DIRSCAN" "$IPS" "$PORTSCAN" "$ARCHIVE" "$NUCLEISCAN" "$GFSCAN"
}

: 'Gather resolvers'
gatherResolvers() {
	startFunction "Downloading fresh resolvers"
	wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O "$IPS"/resolvers.txt
}

: 'subdomain gathering'
gatherSubdomains() {
	startFunction "sublert"
	echo -e "[$GREEN+$RESET] Checking for existing sublert output, otherwise add it."
	if [ ! -e "$SUBS"/sublert.txt ]; then
		cd "$HOME"/tools/sublert || return
		yes | python3 sublert.py -u "$domain"
		cp "$HOME"/tools/sublert/output/"$domain".txt "$SUBS"/sublert.txt
		cd "$HOME" || return
	else
		cp "$HOME"/tools/sublert/output/"$domain".txt "$SUBS"/sublert.txt
	fi
	echo -e "[$GREEN+$RESET] Done, next."

	startFunction "subfinder"
	"$HOME"/go/bin/subfinder -d "$domain" -all -config "$HOME"/nullbot/modules/recon/configs/config.yaml -o "$SUBS"/subfinder.txt
	echo -e "[$GREEN+$RESET] Done, next."

	startFunction "assetfinder"
	"$HOME"/go/bin/assetfinder --subs-only "$domain" >"$SUBS"/assetfinder.txt
	echo -e "[$GREEN+$RESET] Done, next."

	startFunction "amass"
	"$HOME"/go/bin/amass enum -passive -d "$domain" -config "$HOME"/nullbot/modules/recon/configs/config.ini -o "$SUBS"/amassp.txt
	echo -e "[$GREEN+$RESET] Done, next."

	startFunction "findomain"
	findomain -t "$domain" -u "$SUBS"/findomain_subdomains.txt
	echo -e "[$GREEN+$RESET] Done, next."

	startFunction "rapiddns"
	crobat -s "$domain" | sort -u | tee "$SUBS"/rapiddns_subdomains.txt
	echo -e "[$GREEN+$RESET] Done, next."

	echo -e "[$GREEN+$RESET] Combining and sorting results.."
	cat "$SUBS"/*.txt | sort -u >"$SUBS"/subdomains
	echo -e "[$GREEN+$RESET] Resolving subdomains.."
	cat "$SUBS"/subdomains | sort -u | shuffledns -silent -d "$domain" -r "$IPS"/resolvers.txt > "$SUBS"/alive_subdomains
	echo -e "[$GREEN+$RESET] Getting alive hosts.."
	httpx -l "$SUBS"/subdomains -silent -threads 9000 -timeout 30 | anew "$SUBS"/hosts
	cat "$SUBS"/alive_subdomains | "$HOME"/go/bin/httprobe | tee "$SUBS"/hosts_httprobe
	echo -e "[$GREEN+$RESET] Done."
}

: 'subdomain takeover check'
checkTakeovers() {
	startFunction "subjack"
	"$HOME"/go/bin/subjack -w "$SUBS"/hosts -a -ssl -t 50 -v -c "$HOME"/go/src/github.com/haccer/subjack/fingerprints.json -o "$SUBS"/all-takeover-checks.txt -ssl
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
	nuclei -l "$SUBS"/hosts -t "$HOME"/nuclei-templates/takeovers -c 50 -o "$SUBS"/nuclei-takeover-checks.txt
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
	dnsprobe -r CNAME -l "$SUBS"/subdomains -o "$SUBS"/subdomains_cname.txt
}

: 'Gather IPs with dnsprobe'
gatherIPs() {
	startFunction "dnsprobe"
	dnsprobe -l "$SUBS"/subdomains -silent -f ip | sort -u | tee "$IPS"/"$domain"-ips.txt
	python3 $HOME/nullbot/modules/recon/scripts/clean_ips.py "$IPS"/"$domain"-ips.txt "$IPS"/"$domain"-origin-ips.txt
	echo -e "[$GREEN+$RESET] Done."
}

: 'Portscan on found IP addresses'
portScan() {
	startFunction  "Port Scan"
	cd "$PORTSCAN" || return
	naabu -p - -silent -exclude-cdn -nmap -config "$HOME"/nullbot/modules/recon/configs/naabu.conf -o "$PORTSCAN"/naabu -iL "$SUBS"/alive_subdomains
	cd - || return
	echo -e "[$GREEN+$RESET] Port Scan finished"
}

: 'Gather screenshots'
gatherScreenshots() {
	startFunction "Screenshot Gathering"
	# Bug in aquatone, once it gets fixed, will enable aquatone on x86 also.
	arch=`uname -m`
	if [[ "$arch" == "x86_64" ]]; then
        python3 $HOME/tools/EyeWitness/Python/EyeWitness.py -f "$SUBS"/hosts --no-prompt -d "$SCREENSHOTS"
	else
	cat "$SUBS"/hosts | aquatone -http-timeout 10000 -ports xlarge -out "$SCREENSHOTS"
	fi
	echo -e "[$GREEN+$RESET] Screenshot Gathering finished"
}

fetchArchive() {
	startFunction "fetchArchive"
	cat "$SUBS"/hosts | sed 's/https\?:\/\///' | gau > "$ARCHIVE"/getallurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | unfurl --unique keys > "$ARCHIVE"/paramlist.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.js(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > "$ARCHIVE"/jsurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.php(\?|$) | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u " > "$ARCHIVE"/phpurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.aspx(\?|$) | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u " > "$ARCHIVE"/aspxurls.txt
	cat "$ARCHIVE"/getallurls.txt  | sort -u | grep -P "\w+\.jsp(\?|$) | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u " > "$ARCHIVE"/jspurls.txt
	echo -e "[$GREEN+$RESET] fetchArchive finished"
}

fetchEndpoints() {
	startFunction "fetchEndpoints"
	for js in `cat "$ARCHIVE"/jsurls.txt`;
	do
		python3 "$HOME"/tools/LinkFinder/linkfinder.py -i $js -o cli | anew "$ARCHIVE"/endpoints.txt;
	done
	echo -e "[$GREEN+$RESET] fetchEndpoints finished"
}

: 'Gather information with meg'
startMeg() {
	startFunction "meg"
	cd "$SUBS" || return
	meg -d 1000 -v /
	mv out meg
	cd "$HOME" || return
}

: 'Use gf to find secrets in responses'
startGfScan() {
	startFunction "Checking for secrets using gf"
	cd "$SUBS"/meg || return
	for i in `gf -list`; do [[ ${i} =~ "_secrets"* ]] && gf ${i} >> "$GFSCAN"/"${i}".txt; done
	cd "$HOME" || return
}

: 'directory brute-force'
startBruteForce() {
	startFunction "directory brute-force"
	#cat "$SUBS"/hosts | parallel -j 5 --bar --shuf gobuster dir -u {} -t 50 -w "$HOME"/tools/SecLists/Discovery/Web-Content/raft-medium-directories.txt -e -r -k -q -o "$DIRSCAN"/"$sub".txt
	python3 ~/tools/dirsearch/dirsearch.py -l "$SUBS"/hosts -o "$DIRSCAN"/default.txt -t 100
	#python3 ~/tools/dirsearch/dirsearch.py -l "$SUBS"/hosts -w "$HOME"/tools/SecLists/Discovery/Web-Content/raft-medium-directories.txt -o "$DIRSCAN"/raft-dir.txt -t 100 #-e txt,php,html -f 
}

#Needs to be checked
: 'Check open redirects'
startOpenRedirect() {
	startFunction "gf open redirect"
	cat "$SUBS"/hosts | gau | httpx -silent -timeout 2 -threads 100 | gf redirect | anew "$RESULTDIR"/openredirects.txt 
	cd "$HOME" || return
}

: 'Check for Vulnerabilities'
runNuclei() {
	startFunction  "Nuclei Defaults Scan"
	nuclei -l "$SUBS"/hosts -c 100 -rl 500 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/default-scan.txt
	#startFunction  "Nuclei Custom Detection"
	#nuclei -l "$SUBS"/hosts -t "$HOME"/nuclei-templates/cves/ -c 50 -H "x-bug-bounty: $hackerhandle" -o "$NUCLEISCAN"/cve.txt
	echo -e "[$GREEN+$RESET] Nuclei Scan finished"
}

notifySlack() {
	startFunction "Trigger Slack Notification"
	source "$HOME"/nullbot/modules/recon/configs/tokens.txt
	export SLACK_WEBHOOK_URL="$SLACK_WEBHOOK_URL"
	echo -e "ReconPi $domain scan completed!" | slackcat
	totalsum=$(cat $SUBS/hosts | wc -l)
	echo -e "$totalsum live subdomain hosts discovered" | slackcat

	posibbletko="$(cat $SUBS/takeovers | wc -l)"
	if [ -s "$SUBS/takeovers" ]
		then
        echo -e "Found $posibbletko possible subdomain takeovers." | slackcat
	else
        echo "No subdomain takeovers found." | slackcat
	fi

	if [ -f "$NUCLEISCAN/cve.txt" ]; then
	echo "CVE's discovered:" | slackcat
    cat "$NUCLEISCAN/cve.txt" | slackcat
		else 
    echo -e "No CVE's discovered." | slackcat
	fi

	if [ -f "$NUCLEISCAN/files.txt" ]; then
	echo "files discovered:" | slackcat
    cat "$NUCLEISCAN/files.txt" | slackcat
		else 
    echo -e "No files discovered." | slackcat
	fi

	echo -e "[$GREEN+$RESET] Done."
}

notifyDiscord() {
	startFunction "Trigger Discord Notification"
	intfiles=$(cat $NUCLEISCAN/*.txt | wc -l)

	source "$HOME"/nullbot/modules/recon/configs/tokens.txt
	export DISCORD_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"

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

source "$HOME"/nullbot/modules/recon/configs/tokens.txt || return
export SLACK_WEBHOOK_URL="$SLACK_WEBHOOK_URL"

startRecon
checkArguments
checkDirectories
gatherResolvers
gatherSubdomains
checkTakeovers
getCNAME
gatherIPs
startMeg
fetchArchive
fetchEndpoints
startGfScan
gatherScreenshots
startOpenRedirect
runNuclei
portScan
startBruteForce
#notifySlack
#notifyDiscord
