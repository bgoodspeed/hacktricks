Major gaps:

  * Web vulnerabilities (src/pentesting-web/ — 73 pages)
      SQLi, XSS, SSRF, SSTI, XXE, file upload, deserialization, request smuggling, CORS, CSP bypass, etc. These are the most-queried topics in practice. You'd query hacktricks sqli or hacktricks xss and
       get payload cheatsheets + commands.

  * Privilege escalation (src/linux-hardening/privilege-escalation/, src/windows-hardening/windows-local-privilege-escalation/)
  These are the most-reached-for pages during a box. Commands to check SUIDs, writable paths, cron jobs, token abuse, etc. Natural queries: hacktricks privesc linux, hacktricks privesc windows.


  * Cross-cutting post-exploitation techniques (src/generic-methodologies-and-resources/)
      - exfiltration.md — how to get data out
      - tunneling-and-port-forwarding.md — socat, chisel, ssh tunnels
      - brute-force.md — wordlists, tool invocations by target type
      - search-exploits.md — searchsploit, exploit-db patterns

  * Reverse shells — highly referenced, not in the index at all, there is a related repo, the one that backs revshells.com, we need a cli version of that, but it's separate


* nice to have: a tool to autocorrect the name if we miss one: e.g. there is a key "active-directory", but user says "ad" or "activedirectory", or "active directory" or something with a mild typo.  like a "did you mean XYZ?"

* eventual goal (separate project) to tie this together: a tool to build a checklist for exploits to try, the checklist should be a runnable test suite (pytest or similar), iteratively built: first pass, basic nmap scan or even IP => prompt for nmap, => ports => prompt for service banner check => banner /port/service X => prompt for the tests /tricks specified 
