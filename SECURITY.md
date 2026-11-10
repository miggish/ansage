# Security

ansage talks BGP to routers and can change the kernel's routing table, so we
treat bugs that let a neighbor or a local user crash it, hijack or leak routes,
or get past TCP-MD5, GTSM or the control socket's permissions as security
issues.

## Reporting

Write to **security@ansage.sh**. Please do not open a public issue.

Include the ansage version (`ansage --version`), the relevant part of the
config (without keys) and, if you can, the BGP messages or steps that trigger
it. We answer within a few days and agree on a disclosure date with you.

## Supported versions

Fixes go into the latest release.
