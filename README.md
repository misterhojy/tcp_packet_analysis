Instructions:
run in terminal
` python3 analysis_pcap_tcp.py assignment2.pcap `
- Pass PCAP file as command line parameter (must be in directory)

Summary:
What we do is we have a dictionary to split each flow. To determine a flow we identify the SYN as there are only 1 SYN per flow.
Using the dpkt library we can dissect the packet and get info like (source port, source addr, dest port, dest addr).
We find the first 2 transactions after the connection and get the seq, ack and calculate the window size.
To calc window size we get the window size factor is from the SYN packet options in the TCP header and we multiply with tcp.win.
We also calculate RTT by getting the time it takes to get the correct ACK response.
From that we calculate congestion window size which is the amount of packets is sent in between RTT intervals.
To get Retransmission I  count how many seq number were encountered more than once. If the time between the latest dupelicate seq and the initial is > 2 * RTT then it is a time out. The rest would be triple dupelicate Ack.
Throughough put was calculated by getting the start time and all the summed data and the end time. divide sum data by the time it took
