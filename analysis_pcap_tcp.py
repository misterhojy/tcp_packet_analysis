import dpkt
import argparse
import socket

def analysis_pcap_tcp(file_path):
    sender = '130.245.145.12'
    receiver = '128.208.2.198'
    flows = {}  # Main dictionary where key is flow_id and value is dict of attributes

    file = open(file_path, 'rb')
    pcap = dpkt.pcap.Reader(file)                           # Open and read PCAP File
    
    for ts, buf in pcap:                                     # Parsed into python objects
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        tcp_header_length = tcp.off * 4
        total_tcp_segment_length = len(ip.data)
        tcp_payload_size = total_tcp_segment_length - tcp_header_length

        saddr = socket.inet_ntoa(ip.src)                     # convert from byte
        daddr = socket.inet_ntoa(ip.dst)
        # (source port, source IP address, destination port, destination IP address)
        if (saddr == sender and daddr == receiver):
            flow_id = (tcp.sport, saddr, tcp.dport, daddr)      # create a unique identifier for each flow

            if ((tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK)):
                flows[flow_id] = {
                'packets': 0,
                'transactions': 0,
                'times': [ts, ts],
                'seq': [],
                'ack': [],
                'win': [],
                'total_data_sent': 0,
                'RTT': 0,
                'RTT_payload': 0,
                'RTT_times': [ts, ts],
                'factor': 1,
                'cwnd': [],
                'retransmissions': 0,
                'timeouts': 0,
                'triple': 0,
                'seq_record': {}
                }
                options = dpkt.tcp.parse_opts(tcp.opts)
                for option in options:
                    if (option[0] == dpkt.tcp.TCP_OPT_WSCALE):
                        flows[flow_id]['factor'] = 2**option[1][0]

            elif (tcp.flags & dpkt.tcp.TH_ACK):
                flows[flow_id]['total_data_sent'] +=  tcp_payload_size     # get TCP length for each ACK packet from sender
                if (flows[flow_id]['packets'] == 2 and tcp_payload_size > 0):    # Ack piggy back
                    flows[flow_id]['seq'].append(tcp.seq)
                    flows[flow_id]['ack'].append(tcp.ack)
                    flows[flow_id]['win'].append(tcp.win * flows[flow_id]['factor'])
                    flows[flow_id]['transactions'] += 1

                elif (flows[flow_id]['packets'] > 2 and flows[flow_id]['transactions'] < 3):              # First two transactions after the handshake
                    flows[flow_id]['seq'].append(tcp.seq)
                    flows[flow_id]['ack'].append(tcp.ack)
                    flows[flow_id]['win'].append(tcp.win * flows[flow_id]['factor'])
                    flows[flow_id]['transactions'] += 1

                # if the time stamp between 1 RTT nand 2 RTT 
                if (len(flows[flow_id]['cwnd']) < 3):
                    if (ts - flows[flow_id]['times'][0] > flows[flow_id]['RTT'] and ts - flows[flow_id]['times'][0] <= 2 * flows[flow_id]['RTT']):
                        if (len(flows[flow_id]['cwnd']) < 2):
                            flows[flow_id]['cwnd'].append(0)
                        flows[flow_id]['cwnd'][1] += 1

                if (len(flows[flow_id]['cwnd']) <= 3):
                    if (ts - flows[flow_id]['times'][0] > 2 * flows[flow_id]['RTT'] and ts - flows[flow_id]['times'][0] <= 3 * flows[flow_id]['RTT']):
                        if (len(flows[flow_id]['cwnd']) < 3):
                            flows[flow_id]['cwnd'].append(0)
                        flows[flow_id]['cwnd'][2] += 1

                flows[flow_id]['times'][1] = ts

                if (flows[flow_id]['packets'] > 2):
                    if (tcp.seq not in flows[flow_id]['seq_record']):
                        flows[flow_id]['seq_record'][tcp.seq] = {'initial': ts, 'timestamp': ts, 'dupe': False}
                    else:
                        flows[flow_id]['seq_record'][tcp.seq]['timestamp'] = ts  # Might be redundant
                        flows[flow_id]['seq_record'][tcp.seq]['dupe'] = True
                        flows[flow_id]['retransmissions'] += 1
        else:
            flow_id = (tcp.dport, daddr, tcp.sport, saddr)

        if ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)):
            flows[flow_id]['RTT_times'][1] = ts
            flows[flow_id]['RTT'] = (flows[flow_id]['RTT_times'][1] - flows[flow_id]['RTT_times'][0])
            flows[flow_id]['cwnd'].append(1)

        
        flows[flow_id]['packets'] += 1

    

    print("Number of TCP Flows: ", len(flows))
    for key in flows:

        for seq, record in flows[key]['seq_record'].items():
            if record['dupe']:
                ts = record['timestamp']
                initial = record['initial']
                if ((ts - initial) > 2 * flows[key]['RTT']):
                    flows[key]['timeouts'] += 1
                flows[key]['triple'] = flows[key]['retransmissions'] - flows[key]['timeouts']

        time_period = flows[key]['times'][1] - flows[key]['times'][0] 
        throughput = (flows[key]['total_data_sent'] / time_period) if time_period > 0 else 0 
        print(f"FLOW: {key}")
        # print(f"\tStart Time: {flows[key]['times'][1]} End Time: {flows[key]['times'][0]}")
        print(f"\tTransaction #1 (Seq: {flows[key]['seq'][0]}, Ack: {flows[key]['ack'][0]}, Calc Win: {flows[key]['win'][0]})")
        print(f"\tTransaction #2 (Seq: {flows[key]['seq'][1]}, Ack: {flows[key]['ack'][1]}, Calc Win: {flows[key]['win'][1]})")
        print(f"\tCongestion Window Sizes {flows[key]['cwnd']}")
        # print(f"\tPackets: {flows[key]['packets']}")
        # print(f"\tRTT: {flows[key]['RTT']}")
        print(f"\tThroughput: {throughput} bytes/sec")
        # print(f"\tRetransmissions: {flows[key]['retransmissions']}")
        print(f"\tRetransmissions due to Timeouts: {flows[key]['timeouts']}")
        print(f"\tRetransmissions due to Triple Dupe ACKs: {flows[key]['triple']}")


def main():
    # Adding Command Line Arguments, accepting a valid file
    parser = argparse.ArgumentParser(description="Analyze a pcap TCP dump file.")
    parser.add_argument("file", type=str, help="The path to the file to analyze")
    args = parser.parse_args()
    analysis_pcap_tcp(args.file)

if __name__ == "__main__":
    main()