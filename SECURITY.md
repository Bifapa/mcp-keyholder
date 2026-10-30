# Security policy

MCP Keyholder guards API keys, so security reports get priority over everything else.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting). If that is not available to you, open an issue that only asks for a private contact, without details.

Include what you can:

- the version (Settings → About) and the mode (portable or service);
- what an attacker needs: an agent with MCP access, a process of the same user, local admin, physical access;
- steps to reproduce and what you expected instead.

We reply within 7 days and keep you updated until the fix ships. Credit is given in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release gets security fixes. The app updates itself; check Settings → About → Check for updates.

## Scope

The threat model is in [CONCEPT.md §11](CONCEPT.md) (in Russian). In short, these are in scope:

- an agent getting a value without a matching approval;
- forging or replaying an approval;
- reading values from disk, logs or crash dumps;
- tampering with policies or the audit log without detection;
- impersonating the approval window.

Out of scope:

- an attacker with administrator rights on the machine;
- a compromised authenticator device together with the master password;
- portable mode against a process that deliberately reads the app's memory (service mode covers that).
