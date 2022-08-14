from scapy.all import *
from scapy.layers.inet import IP
import pandas as pd

def analyze_data(file_name, pkt_writer):
    packets = PcapReader(file_name)

    df = []

    for pkt in packets:
        if IP in pkt:
            source_IP = pkt[IP].src
            dest_IP = pkt[IP].dst
            packet_size = pkt.sprintf("%IP.len%")
            arrival_time = pkt.time

            df.append(
                {
                    'Source IP': source_IP,
                    'Destination IP': dest_IP,
                    'Packet Size': packet_size,
                    'Arrival Time': arrival_time
                }
            )

    packets_data = pd.DataFrame(df)

    packets_data.to_excel(pkt_writer, sheet_name = file_name, index = False)



def main():

    writer = pd.ExcelWriter('MP5_Statistics.xlsx')

    analyze_data('amazon.pcap', writer)
    analyze_data('github.pcap', writer)
    analyze_data('georgetown.pcap', writer)
    analyze_data('netflix.pcap', writer)
    analyze_data('reddit.pcap', writer)

    writer.save()



if __name__ == '__main__':
    main()