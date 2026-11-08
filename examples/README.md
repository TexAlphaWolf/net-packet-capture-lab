# Examples

```bash
pcaplab sample -o demo.pcap --seed 7 --truth truth.json   # a capture with known content (truth.json says what is in it)
pcaplab findings demo.pcap                                 # what looks wrong; exit code 1 if anything
pcaplab report demo.pcap -o report.html                    # the same, as one page
```

[`ssh-capture.sh`](ssh-capture.sh) shows how to take a real capture on a Linux server and look at it, and
[`filters.txt`](filters.txt) lists filter expressions for common questions.
