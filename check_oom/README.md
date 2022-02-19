# icinga2_check_oom
Icinga2/Nagios check for Out of memory problems. ATM it check all dmesg output. If you want after check make it green again, you need to run dmesg -c.

```bash
usage: check_oom.py [-h] [-m {warning,critical,default}] [-v]

Check for OOM killer events

optional arguments:
  -h, --help            show this help message and exit
  -m {warning,critical,default}, --mode {warning,critical,default}
                        Mode of results for this check: warning, critical,
                        default
  -s, --short           If this option is specified, check ignores dmesg OOM
                          problems older then 24 hours
  -v, --verbose         Show verbose output from demsg about OOM killer events

check_oom.py: v.1.1 by Dmytro Prokhorenkov
```

