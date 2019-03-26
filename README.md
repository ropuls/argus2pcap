# argus2pcap
Converts an argus isdn text trace into a wireshark capture file (aka eyesdn)

# Requirements
- g++7 or newer (using -std=c++17)
- WinAnalyze from Intec GmbH with a valid license file to export .itf as textual trace

# caveats
- the software is simply parsing out hex strings from the input and writing output to the output file. Parsing happens with german keywords, so you will fail with Winanalyse versions that are non-german
- the output file is not a real pcap file, but eyesdn file format, which is quite brain-dead. However, it cannot be read by tcpdump and friends, but only with wireshark and tshark

