# security model

SuperiorSec runs locally. it reads Linux files and settings. it does not change kernel settings or firewall rules. it does not start services. the usual commands do not need root.

## data and reports

the inspection commands print results to the terminal or to the file you choose.

process command lines and socket addresses can reveal details about a machine. check reports before you save or share them.

`integrity init` writes a SHA-256 manifest to the path you choose. the default is in your state directory. it will not replace an existing manifest unless you use `--force`.

`integrity check` reads the manifest and the selected files. it does not change those files.

integrity checks compare file contents only. they do not check file owners or permissions. they also ignore timestamps and extended attributes. the manifest is not signed. keep it somewhere separate from the files you check.

the scanner skips symlinks. unreadable files are reported as errors. it will not write a new baseline if the scan has errors.

## limits

Linux permissions can hide some process and socket details. the audit checks a few settings. it is not a full audit or compliance report. the firewall check runs `nft list ruleset` or `iptables -S` when either tool is installed. the result can be unknown if the current user cannot read the rules.

use SuperiorSec only on systems you own or are allowed to inspect. check findings before changing system settings.
