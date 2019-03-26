# argus2pcap
Converts an argus isdn text trace into a wireshark capture file (aka eyesdn)

## Requirements
- g++7 or newer (using -std=c++17), and a linux host for now
- WinAnalyze from Intec GmbH with a valid license file to export .itf as textual trace

## Caveats
- the software is simply parsing out hex strings from the input and writing output to the output file. Parsing happens with german keywords, so you will fail with Winanalyse versions that are non-german
- the output file is not a real pcap file, but eyesdn file format, which is quite brain-dead. However, it cannot be read by tcpdump and friends, but only with wireshark and tshark

## Example

First, from WinAnalyse, select File - Export Trace and save the file as
trace.txt. This requires you to have a valid license for WinAnalyse.

```

#> head trace.txt
This file was created from the following program:
WINanalyse Version: 3.14.060219
Date: 26.03.2019  10:29
Tracefile: ArgusTrace2.itf

#>  ~/src/argus2pcap/bin/a2w trace.txt out.pcap

#> tshark -r out.pcap q931 |head
  3   0.005000         User -> Network      Q.931 15 TEI:66 I, N(R)=1, N(S)=0 | CALL PROCEEDING
  4   0.928000         User -> Network      Q.931 36 TEI:127 U, func=UI | SETUP
  5   0.928000         User -> Network      Q.931 12 TEI:66 I, N(R)=1, N(S)=1 | PROGRESS
 10   0.933000         User -> Network      Q.931 8 TEI:68 I, N(R)=1, N(S)=0 | CONNECT ACKNOWLEDGE
 11   0.933000      Network -> User         Q.931 11 TEI:65 I, N(R)=0, N(S)=0 | CALL PROCEEDING
 12   0.935000         User -> Network      Q.931 27 TEI:66 I, N(R)=1, N(S)=2 | CONNECT
 14   0.937000         User -> Network      Q.931 12 TEI:65 I, N(R)=1, N(S)=0 | RELEASE
 16   0.938000      Network -> User         Q.931 8 TEI:65 I, N(R)=1, N(S)=1 | ALERTING
 19   0.941000         User -> Network      Q.931 15 TEI:65 I, N(R)=2, N(S)=1 | STATUS
 21   0.942000      Network -> User         Q.931 8 TEI:65 I, N(R)=2, N(S)=2 | RELEASE COMPLETE

```
