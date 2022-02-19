# check_vgfree
Nagios plugin to check free space on LVM volume group

```console
$ chmod +x check_vgfree
$ ./check_vgfree --help
Usage: check_vgfree [options]
  try: check_vgfree --help

Options:
  -h, --help            show this help message and exit
  -c CRITICAL, --critical=CRITICAL
                        critical size limit
  -C CP, --critical-percent=CP
                        % critical limit
  -g VG, --volume-group=VG
                        volume group to check
  -w WARNING, --warning=WARNING
                        warning size limit
  -W WP, --warning-percent=WP
                        % warning limit
  --units=UNIT          size in these units: (b)ytes, (k)ilobytes,
                        (m)egabytes, *(g)igabytes (*DEFAULT), (t)erabytes,
                        (p)etabytes, (e)xabytes
```
