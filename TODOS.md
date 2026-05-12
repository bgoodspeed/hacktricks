Major gaps:

  * look into lolbas https://github.com/LOLBAS-Project/LOLBAS
 
*  and gtfobins , add to this

  * consider getting the info out of the security briefings thing too

  * Reverse shells — highly referenced, not in the index at all, there is a related repo, the one that backs revshells.com, we need a cli version of that, but it's separate: https://github.com/0dayCTF/reverse-shell-generator



* eventual goal (separate project) to tie this together: a tool to build a checklist for exploits to try, the checklist should be a runnable test suite (pytest or similar), iteratively built: first pass, basic nmap scan or even IP => prompt for nmap, => ports => prompt for service banner check => banner /port/service X => prompt for the tests /tricks specified 
