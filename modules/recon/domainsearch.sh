BASE="$HOME/tools"
. "${BASE}/nullbot/modules/recon/functions.sh"


checkArguments
checkDirectories
gatherResolvers
gatherSubdomains
getCNAME
gatherIPs
checkTakeovers