pip install -e tools/hacktricks-cli 


Usage:
  hacktricks 3389           # port → service + all commands
  hacktricks smb            # service name (exact or fuzzy)
  hacktricks smb -c enum    # filter to enumeration only
  hacktricks --list         # all 77 services
  hacktricks rdp --plain    # grep-friendly output
  hacktricks rdp --json     # JSON for scripting
  hacktricks --info         # index version + source commit


