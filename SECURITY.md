# Security policy

vetcode is a security tool, so two kinds of report matter:

- **A way to make vetcode miss something** (malware or a vulnerability that a variation of a pattern slips past, or text that steers Claude into skipping a finding).
- **A bug in vetcode itself** that could hurt the person running it (for example, if scanning a hostile repository could execute code or leak data).

Please report these privately through [GitHub's private vulnerability reporting](https://github.com/openyard-cloud/vetcode/security/advisories/new) rather than a public issue. Include a minimal sample if you can; build it so it does not work as real malware (a harmless payload is enough).

We aim to reply within a week. False positives and missing rules for ordinary vulnerabilities are welcome as normal issues or pull requests.
