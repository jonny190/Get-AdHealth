
# Check Active Directory Health Script 

This is a quick and dirty script to check the health of a given DC. This will likely seen lots of revisions and chages as it developes


## Functions
- Virtual Check
- Replication status
- DCDIAG
- Forest and domain functional Level lookup
- Port test to all DC's on all sites (Port 135)
- Users not logged in within the last 90 day lookup
- Unlinked GPO lookup and list
- RID exhaustion check
- Duplicate SPN lookup
- Time source lookup
- Added DNS Scavenging check
- Lists DNS Forwarders and warns if less then 2

## To Do
### User accounts
- ~~Paswords never expire~~
- ~~Password not req~~
- ~~Users total~~
- ~~Users disabled~~
### Computer accounts
- ~~Stale computer accounts~~
- ~~Total Computers / Servers~~

## Screenshot
![Screenshot](/Images/Get-ADHealth_Screenshot%202023-05-30%20104722.png)

## Authors

- [@Jonny190](https://www.github.com/jonny190)
- [@Spud](https://github.com/jonathan-davies-uk)

