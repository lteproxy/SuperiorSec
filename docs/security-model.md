# Security model

SuperiorSec is a local inspection tool. Its default commands read Linux procfs and sysctl data, operating-system metadata, and selected configuration metadata. They do not write kernel settings, change firewall rules, start background services, or require root.

## Data handling

- `system`, `processes`, `network`, `audit`, and `report` print data to the terminal or to the output file named by the user.
- Process command lines and socket endpoints can be sensitive. Review reports before storing or sharing them.
- `integrity init` creates a SHA-256 manifest at the chosen path. The default is under the user's state directory. It refuses to replace an existing manifest unless `--force` is given.
- `integrity check` reads the manifest and selected files. It does not repair or alter the scanned tree.
- Integrity checks compare file contents only; they do not record ownership, permissions, timestamps, or extended attributes. A manifest is not signed, so keep it somewhere an attacker who can alter the scanned files cannot also replace it.
- Symlinks are not followed by the integrity scanner. Files that cannot be read are reported as errors, and a partial scan does not produce a new baseline.

## Limits

Process and socket details are subject to Linux permission checks and may be incomplete. The hardening checks are a small set of recommendations, not a complete audit or compliance certification. Firewall inspection is best effort: it calls `nft list ruleset` or `iptables -S` when those programs are available, and the current user's permissions may limit the result.

SuperiorSec is intended for systems the operator owns or is authorized to inspect. Findings should be reviewed in context before changing system configuration.
