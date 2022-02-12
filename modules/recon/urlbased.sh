BASE="$HOME/tools"
. "${BASE}/nullbot/modules/recon/functions.sh"

checkArguments
checkDirectories
techDiscovery
getCNAME
gatherIPs
checkTakeovers
fetchArchive
fetchEndpoints
startGfScan
runNuclei
runSpider
runSearch
portScan