
# Tool for Domain User Enumeration via MSSQL

This script is designed to enumerate domain users via MSSQL statements, specifically `SUSER_SNAME()`. This can be used if an MSSQL service is accessible via local credentials and the domain cannot be enumerated (i.e. the user does not have valid domain credentials).

This script was heavily inspired by !"this blog"(https://www.netspi.com/blog/technical-blog/network-pentesting/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/#enumda) which demonstrates how the enumeration process works.

The enumeration process involves utilizing the SID and RID values in the domain to discover users. The function `SUSER_SID()` retrieves the SID for the `Domain Users` group in the target domain and combines a default or customized RID length for enumeration in hexadecimal format. Finally, the function `SUSER_SNAME()` takes the combined SID and RID value and returns that exact object name. RIDs are by default set to 500-512 however this can be modified.

This script was specifically designed for the `Redelegate` Vulnlab machine and essentially serves as an automated script to extract domain usernames.

```
└─$ python3 mssql_domain_user_enum.py -s 'test.domain' -u '(USER)' -p '(PASSWORD)' -o ul.txt
[*] Testing connection to test.domain...
[+] Connection to test.domain established successfully.
[*] Extracting domain NETBIOS name...
[+] Retrieved domain: TEST
[*] Extracting SID for group Domain Users...
[+] Retrieved SID: 0x010[...snip...]847a
[+] Found User: TEST\Administrator
[+] Found User: TEST\Guest
[+] Found User: TEST\krbtgt
[*] Usernames written to "ul.txt"
```

