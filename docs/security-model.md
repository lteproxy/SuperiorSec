# security model

SuperiorSec is a local inspection tool. its default commands read Linux procfs and sysctl data, operating-system metadata, and selected configuration metadata. they do not write kernel settings, change firewall rules, start background services, or require root.

## data handling

- `system`, `processes`, `network`, `audit`, and `report` print data to the terminal or to the output file named by the user.
- process command lines and socket endpoints can be sensitive. Review reports before storing or sharing them.
- `integrity init` creates a SHA-256 manifest at the chosen path. the default is under the user's state directory. it refuses to replace an existing manifest unless `--force` is given.
- `integrity check` reads the manifest and selected files. it does not repair or alter the scanned tree.
- integrity checks compare file contents only. they do not record ownership, permissions, timestamps, or extended attributes. a manifest is not signed, so keep it somewhere an attacker who can alter the scanned files cannot also replace it.
- symlinks are not followed by the integrity scanner. Files that cannot be read are reported as errors, and a partial scan does not produce a new baseline.

## limits

process and socket details are subject to Linux permission checks and may be incomplete. the hardening checks are a small set of recommendations, not a complete audit or compliance certification. firewall inspection is best effort: it calls `nft list ruleset` or `iptables -S` when those programs are available, and the current users permissions may limit the result.

SuperiorSec is intended for systems the operator owns or is authorized to inspect.
