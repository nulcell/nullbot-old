BASE="$HOME/tools"
. "${BASE}/nullbot/modules/recon/reconFunctions.sh"

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
# gatherScreenshots
runNuclei
runSpider
runSearch
portScan
# notifySlack
