# ///////////////////////////////////////////
# /////////    Main Dev Only  ///////////////
# ///////////////////////////////////////////


from datetime import datetime
import numpy as np
import plost
import requests
import streamlit as st
import os
import random
from streamlit_folium import folium_static
from folium.plugins import MarkerCluster
import folium
from scapy.all import rdpcap
import collections
import tempfile
import sys
import pandas as pd
from scapy.utils import corrupt_bytes
from streamlit_echarts import st_echarts
import geoip2.database
import pydeck as pdk
import folium
from streamlit_option_menu import option_menu
# from scapy.layers.inet import IP,TCP,UDP,
from utils.pcap_decode import PcapDecode
import time
import plotly.express as px
# from streamlit_pandas_profiling import st_profile_report
# from folium.plugins import HeatMap

PD = PcapDecode()  # Parser
PCAPS = None  # Packets


if 'uploaded_file' not in st.session_state:
    st.session_state.uploaded_file = None

if 'pcap_data' not in st.session_state:
    st.session_state.pcap_data = None

def get_all_pcap(PCAPS, PD):
    pcaps = collections.OrderedDict()
    for count, i in enumerate(PCAPS, 1):
        pcaps[count] = PD.ether_decode(i)
    return pcaps


def get_filter_pcap(PCAPS, PD, key, value):
    pcaps = collections.OrderedDict()
    count = 1
    for p in PCAPS:
        pcap = PD.ether_decode(p)
        if key == 'Procotol':
            if value == pcap.get('Procotol').upper():
                pcaps[count] = pcap
                count += 1
            else:
                pass
        elif key == 'Source':
            if value == pcap.get('Source').upper():
                pcaps[count] = pcap
                count += 1
        elif key == 'Destination':
            if value == pcap.get('Destination').upper():
                pcaps[count] = pcap
                count += 1
        else:
            pass
    return pcaps


def process_json_data(json_data):
    # Convert JSON data to a pandas DataFrame
    df = pd.DataFrame.from_dict(json_data, orient='index')
    return df


# To Calculate Live Time
def calculate_live_time(pcap_data):
    timestamps = [float(packet.time) for packet in pcap_data]  # Convert to float
    start_time = min(timestamps)
    end_time = max(timestamps)
    live_time_duration = end_time - start_time
    live_time_duration_str = str(pd.Timedelta(seconds=live_time_duration))
    return start_time, end_time, live_time_duration, live_time_duration_str


# protocol length statistics
def pcap_len_statistic(PCAPS):
    pcap_len_dict = {'0-300': 0, '301-600': 0, '601-900': 0, '901-1200': 0, '1201-1500': 0, '1500-more': 0}
    if PCAPS is None:
        return pcap_len_dict
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if 0 < pcap_len < 300:
            pcap_len_dict['0-300'] += 1
        elif 301 <= pcap_len < 600:
            pcap_len_dict['301-600'] += 1
        elif 601 <= pcap_len < 900:
            pcap_len_dict['601-900'] += 1
        elif 901 <= pcap_len < 1200:
            pcap_len_dict['901-1200'] += 1
        elif 1201 <= pcap_len <= 1500:
            pcap_len_dict['1201-1500'] += 1
        elif pcap_len > 1500:
            pcap_len_dict['1500-more'] += 1
        else:
            pass
    return pcap_len_dict


# protocol freq statistics
def common_proto_statistic(PCAPS):
    common_proto_dict = collections.OrderedDict()
    common_proto_dict['IP'] = 0
    common_proto_dict['IPv6'] = 0
    common_proto_dict['TCP'] = 0
    common_proto_dict['UDP'] = 0
    common_proto_dict['ARP'] = 0
    common_proto_dict['ICMP'] = 0
    common_proto_dict['DNS'] = 0
    common_proto_dict['HTTP'] = 0
    common_proto_dict['HTTPS'] = 0
    common_proto_dict['Others'] = 0

    if PCAPS is None:
        return common_proto_dict
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            common_proto_dict['IP'] += 1
        elif pcap.haslayer("IPv6"):
            common_proto_dict['IPv6'] += 1
        if pcap.haslayer("TCP"):
            common_proto_dict['TCP'] += 1
        elif pcap.haslayer("UDP"):
            common_proto_dict['UDP'] += 1
        if pcap.haslayer("ARP"):
            common_proto_dict['ARP'] += 1
        elif pcap.haslayer("ICMP"):
            common_proto_dict['ICMP'] += 1
        elif pcap.haslayer("DNS"):
            common_proto_dict['DNS'] += 1
        elif pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                common_proto_dict['HTTP'] += 1
            elif dport == 443 or sport == 443:
                common_proto_dict['HTTPS'] += 1
            else:
                common_proto_dict['Others'] += 1
        elif pcap.haslayer("UDP"):
            udp = pcap.getlayer("UDP")
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                common_proto_dict['DNS'] += 1
            else:
                common_proto_dict['Others'] += 1
        elif pcap.haslayer("ICMPv6ND_NS"):
            common_proto_dict['ICMP'] += 1
        else:
            common_proto_dict['Others'] += 1
    return common_proto_dict


# maximum protocol statistics
def most_proto_statistic(PCAPS, PD):
    protos_list = list()
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        protos_list.append(data['Procotol'])
    most_count_dict = collections.OrderedDict(collections.Counter(protos_list).most_common(10))
    return most_count_dict


# http/https Protocol Statistics
def http_statistic(PCAPS):
    http_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            dport = tcp.dport
            sport = tcp.sport
            ip = None
            if dport == 80 or dport == 443:
                ip = pcap.getlayer("IP").dst
            elif sport == 80 or sport == 443:
                ip = pcap.getlayer("IP").src
            if ip:
                if ip in http_dict:
                    http_dict[ip] += 1
                else:
                    http_dict[ip] = 1
    return http_dict


def https_stats_main(PCAPS):
    http_dict = http_statistic(PCAPS)
    http_dict = sorted(http_dict.items(),
                       key=lambda d: d[1], reverse=False)
    http_key_list = list()
    http_value_list = list()
    for key, value in http_dict:
        http_key_list.append(key)
        http_value_list.append(value)
    return http_key_list, http_value_list


# DNS Protocol Statistics
def dns_statistic(PCAPS):
    dns_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("DNSQR"):
            qname = pcap.getlayer("DNSQR").qname
            if qname in dns_dict:
                dns_dict[qname] += 1
            else:
                dns_dict[qname] = 1
    return dns_dict


def dns_stats_main(PCAPS):
    dns_dict = dns_statistic(PCAPS)
    dns_dict = sorted(dns_dict.items(), key=lambda d: d[1], reverse=False)
    dns_key_list = list()
    dns_value_list = list()
    for key, value in dns_dict:
        dns_key_list.append(key.decode('utf-8'))
        dns_value_list.append(value)
    return dns_key_list, dns_value_list


def time_flow(PCAPS):
    time_flow_dict = collections.OrderedDict()
    start = PCAPS[0].time
    time_flow_dict[time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(PCAPS[0].time)))] = len(
        corrupt_bytes(PCAPS[0]))
    for pcap in PCAPS:
        timediff = pcap.time - start
        time_flow_dict[float('%.3f' % timediff)] = len(corrupt_bytes(pcap))
    return time_flow_dict


def get_host_ip(PCAPS):
    ip_list = list()
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            ip_list.append(pcap.getlayer("IP").src)
            ip_list.append(pcap.getlayer("IP").dst)
    host_ip = collections.Counter(ip_list).most_common(1)[0][0]
    return host_ip


def data_flow(PCAPS, host_ip):
    data_flow_dict = {'IN': 0, 'OUT': 0}
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            if pcap.getlayer("IP").src == host_ip:
                data_flow_dict['OUT'] += 1
            elif pcap.getlayer("IP").dst == host_ip:
                data_flow_dict['IN'] += 1
            else:
                pass
    return data_flow_dict


def data_in_out_ip(PCAPS, host_ip):
    in_ip_packet_dict = dict()
    in_ip_len_dict = dict()
    out_ip_packet_dict = dict()
    out_ip_len_dict = dict()
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            dst = pcap.getlayer("IP").dst
            src = pcap.getlayer("IP").src
            pcap_len = len(corrupt_bytes(pcap))
            if dst == host_ip:
                if src in in_ip_packet_dict:
                    in_ip_packet_dict[src] += 1
                    in_ip_len_dict[src] += pcap_len
                else:
                    in_ip_packet_dict[src] = 1
                    in_ip_len_dict[src] = pcap_len
            elif src == host_ip:
                if dst in out_ip_packet_dict:
                    out_ip_packet_dict[dst] += 1
                    out_ip_len_dict[dst] += pcap_len
                else:
                    out_ip_packet_dict[dst] = 1
                    out_ip_len_dict[dst] = pcap_len
            else:
                pass

    in_packet_dict = in_ip_packet_dict
    in_len_dict = in_ip_len_dict
    out_packet_dict = out_ip_packet_dict
    out_len_dict = out_ip_len_dict
    in_packet_dict = sorted(in_packet_dict.items(), key=lambda d: d[1], reverse=False)
    in_len_dict = sorted(in_len_dict.items(), key=lambda d: d[1], reverse=False)
    out_packet_dict = sorted(out_packet_dict.items(), key=lambda d: d[1], reverse=False)
    out_len_dict = sorted(out_len_dict.items(), key=lambda d: d[1], reverse=False)
    in_keyp_list = list()
    in_packet_list = list()
    for key, value in in_packet_dict:
        in_keyp_list.append(key)
        in_packet_list.append(value)
    in_keyl_list = list()
    in_len_list = list()
    for key, value in in_len_dict:
        in_keyl_list.append(key)
        in_len_list.append(value)
    out_keyp_list = list()
    out_packet_list = list()
    for key, value in out_packet_dict:
        out_keyp_list.append(key)
        out_packet_list.append(value)
    out_keyl_list = list()
    out_len_list = list()
    for key, value in out_len_dict:
        out_keyl_list.append(key)
        out_len_list.append(value)
    in_ip_dict = {'in_keyp': in_keyp_list, 'in_packet': in_packet_list, 'in_keyl': in_keyl_list, 'in_len': in_len_list,
                  'out_keyp': out_keyp_list, 'out_packet': out_packet_list, 'out_keyl': out_keyl_list,
                  'out_len': out_len_list}
    return in_ip_dict


def proto_flow(PCAPS):
    proto_flow_dict = collections.OrderedDict()
    proto_flow_dict['IP'] = 0
    proto_flow_dict['IPv6'] = 0
    proto_flow_dict['TCP'] = 0
    proto_flow_dict['UDP'] = 0
    proto_flow_dict['ARP'] = 0
    proto_flow_dict['ICMP'] = 0
    proto_flow_dict['DNS'] = 0
    proto_flow_dict['HTTP'] = 0
    proto_flow_dict['HTTPS'] = 0
    proto_flow_dict['Others'] = 0
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if pcap.haslayer("IP"):
            proto_flow_dict['IP'] += pcap_len
        elif pcap.haslayer("IPv6"):
            proto_flow_dict['IPv6'] += pcap_len
        if pcap.haslayer("TCP"):
            proto_flow_dict['TCP'] += pcap_len
        elif pcap.haslayer("UDP"):
            proto_flow_dict['UDP'] += pcap_len
        if pcap.haslayer("ARP"):
            proto_flow_dict['ARP'] += pcap_len
        elif pcap.haslayer("ICMP"):
            proto_flow_dict['ICMP'] += pcap_len
        elif pcap.haslayer("DNS"):
            proto_flow_dict['DNS'] += pcap_len
        elif pcap.haslayer("TCP"):
            tcp = pcap.getlayer("TCP")
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                proto_flow_dict['HTTP'] += pcap_len
            elif dport == 443 or sport == 443:
                proto_flow_dict['HTTPS'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif pcap.haslayer("UDP"):
            udp = pcap.getlayer("UDP")
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                proto_flow_dict['DNS'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif pcap.haslayer("ICMPv6ND_NS"):
            proto_flow_dict['ICMP'] += pcap_len
        else:
            proto_flow_dict['Others'] += pcap_len
    return proto_flow_dict


def most_flow_statistic(PCAPS, PD):
    most_flow_dict = collections.defaultdict(int)
    for pcap in PCAPS:
        data = PD.ether_decode(pcap)
        most_flow_dict[data['Procotol']] += len(corrupt_bytes(pcap))
    return most_flow_dict


def getmyip():
    try:
        headers = {'User-Agent': 'Baiduspider+(+http://www.baidu.com/search/spider.htm'}
        ip = requests.get('http://icanhazip.com', headers=headers).text
        return ip.strip()
    except:
        return None


def get_geo(ip):
    reader = geoip2.database.Reader('utils/GeoIP/GeoLite2-City.mmdb')
    try:
        response = reader.city(ip)
        # city_name = response.country.names['zh-CN']+response.city.names['zh-CN']
        city_name = response.country.names['en'] + response.city.names['en']
        longitude = response.location.longitude
        latitude = response.location.latitude
        return [city_name, longitude, latitude]
    except:
        return None


def get_ipmap(PCAPS, host_ip):
    geo_dict = dict()
    ip_value_dict = dict()
    ip_value_list = list()
    for pcap in PCAPS:
        if pcap.haslayer("IP"):
            src = pcap.getlayer("IP").src
            dst = pcap.getlayer("IP").dst
            pcap_len = len(corrupt_bytes(pcap))
            if src == host_ip:
                oip = dst
            else:
                oip = src
            if oip in ip_value_dict:
                ip_value_dict[oip] += pcap_len
            else:
                ip_value_dict[oip] = pcap_len
    for ip, value in ip_value_dict.items():
        geo_list = get_geo(ip)
        if geo_list:
            geo_dict[geo_list[0]] = [geo_list[1], geo_list[2]]
            Mvalue = str(float('%.2f' % (value / 1024.0))) + ':' + ip
            ip_value_list.append({geo_list[0]: Mvalue})
        else:
            pass
    return [geo_dict, ip_value_list]


# def ipmap(PCAPS):
#     myip = getmyip()
#     host_ip = get_host_ip(PCAPS)
#     ipdata = get_ipmap(PCAPS, host_ip)
#     geo_dict = ipdata[0]
#     ip_value_list = ipdata[1]
#     myip_geo = get_geo(myip)
#     ip_value_list = [(list(d.keys())[0], list(d.values())[0])
#                      for d in ip_value_list]
#     # print('ip_value_list', ip_value_list)
#     # print('geo_dict', geo_dict)
#     # return render_template('./dataanalyzer/ipmap.html', geo_data=geo_dict, ip_value=ip_value_list, mygeo=myip_geo)
#     return geo_dict, ip_value_list, myip_geo


def ipmap(PCAPS):
    # Assuming these functions are defined elsewhere in your code
    myip = getmyip()
    host_ip = get_host_ip(PCAPS)
    ipdata = get_ipmap(PCAPS, host_ip)
    geo_dict = ipdata[0]
    ip_value_list = ipdata[1]
    myip_geo = get_geo(myip)
    ip_value_list = [(list(d.keys())[0], list(d.values())[0]) for d in ip_value_list]

    # Create DataFrames from the dictionaries and lists
    geo_df = pd.DataFrame(list(geo_dict.items()), columns=['Location', 'Coordinates'])
    ip_df = pd.DataFrame(ip_value_list, columns=['Location', 'IP'])

    # Check if myip_geo is not None before creating the DataFrame
    # if myip_geo is not None:
    #     myip_geo_df = pd.DataFrame(myip_geo, columns=['MyLocation', 'MyCoordinates'])
    #
    #     # Merge the DataFrames based on the 'Location' column
    #     merged_df = geo_df.merge(ip_df, on='Location', how='left').merge(myip_geo_df, left_on='Location',
    #                                                                      right_on='MyLocation', how='left')
    # else:
    #     # If myip_geo is None, merge only geo_df and ip_df
    merged_df = geo_df.merge(ip_df, on='Location', how='left')

    # Split the 'IP' column into 'Numeric_Value' and 'IP_Address'
    merged_df[['Data_Traffic', 'IP_Address']] = merged_df['IP'].str.split(':', expand=True)

    # Drop the original 'IP' column
    merged_df = merged_df.drop('IP', axis=1)
    # print("merged_df>>", merged_df)

    # Display the merged DataFrame
    with st.expander("Geo Data Associated with PCAPs "):
        st.write(merged_df)

    return merged_df


def page_file_upload():
    # # File upload
    # uploaded_file = st.file_uploader("Choose a CSV file", type=["csv","pcap", "cap"])
    #
    # # Store the uploaded file in session state
    # st.session_state.uploaded_file = uploaded_file
    #
    # if uploaded_file is not None:
    #     st.success("File uploaded successfully!")
    if "uploaded_file" not in st.session_state or st.session_state.uploaded_file is None:
        # File upload
        uploaded_file = st.file_uploader("Choose a CSV file", type=["csv", "pcap", "cap"])

        # Store the uploaded file in session state
        st.session_state.uploaded_file = uploaded_file

        if uploaded_file is not None:
            st.success("File uploaded successfully!")
    else:
        # Display existing file info
        st.warning("An uploaded file already exists in the session state.")

        # Option to delete existing file and upload a new one
        delete_existing = st.button("Delete Existing File and Upload New File")
        if delete_existing:
            st.session_state.uploaded_file = None
            st.success("Existing file deleted. Please upload a new file.")
            page_file_upload()


def page_display_info():
    # Display uploaded file information
    if st.session_state.get("uploaded_file") is not None:
        # st.subheader("Uploaded File Information:")
        # st.write(f"File Name: {st.session_state.uploaded_file.name}")
        # st.write(f"File Type: {st.session_state.uploaded_file.type}")
        # st.write(f"File Size: {st.session_state.uploaded_file.size} bytes")
        file_details = {"File Name": st.session_state.uploaded_file.name,
                        "File Type": st.session_state.uploaded_file.type,
                        "File Size": st.session_state.uploaded_file.size}
        st.write(file_details)


def Intro():
    # Introduction
    st.markdown(
        """
        Packet Capture (PCAP) files are a common way to store network traffic data. They contain information about
        the packets exchanged between devices on a network. This data is crucial for network analysis and cybersecurity.
        
        ## Support
        
        [![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png)](https://www.buymeacoffee.com/pareshmakwha)
   
 
        ## What is a PCAP file?

        A PCAP file (Packet Capture) is a binary file that stores network traffic data. It records the details of
        each packet, such as source and destination addresses, protocol, and payload. PCAP files are widely used by
        network administrators, security professionals, and researchers to analyze network behavior.

        ## Importance in Cybersecurity

        PCAP files play a vital role in cybersecurity for several reasons:

        - **Network Traffic Analysis:** Analyzing PCAP files helps detect anomalies, identify patterns, and
          understand network behavior.

        - **Incident Response:** In the event of a security incident, PCAP files can be instrumental in
          reconstructing the sequence of events and identifying the root cause.

        - **Forensic Investigations:** PCAP files provide a detailed record of network activity, aiding in
          forensic investigations to determine the source and impact of security incidents.
          
          
        ## Download Sample File 
        Sample 1 [here](https://github.com/paresh2806/PCAP-Analyzer/blob/master/ftp3.pcap)  \n
    
        Sample 2 [here](https://github.com/paresh2806/PCAP-Analyzer/blob/master/ftp-data.pcap)

        ## Getting Started

        To get started with PCAP analysis, you can use tools like Wireshark or tshark. Additionally, Python
        libraries such as Scapy and PyShark provide programmatic access to PCAP data.

        ```python
        # Example using Scapy
        from scapy.all import rdpcap

        # Load PCAP file
        pcap_file = "example.pcap"
        packets = rdpcap(pcap_file)

        # Analyze packets
        for packet in packets:
            # Perform analysis here
            pass
        ```

        Explore the capabilities of PCAP analysis tools to enhance your understanding of network traffic and
        strengthen cybersecurity practices.

        """
    )


def RawDataView():
    uploaded_file = st.session_state.uploaded_file
    if uploaded_file is not None:
        # Check if the uploaded file is a PCAP file
        if uploaded_file.type == "application/octet-stream":
            # Process the uploaded PCAP file
            pcap_data = rdpcap(os.path.join(uploaded_file.name))
            st.session_state.pcap_data = pcap_data
            # Example: Get all PCAPs
            all_data = get_all_pcap(pcap_data, PD)
            dataframe_data = process_json_data(all_data)
            start_time, end_time, live_time_duration, live_time_duration_str = calculate_live_time(pcap_data)

            # Add live time information to the data frame
            # dataframe_data['Start Time'] = start_time
            # dataframe_data['End Time'] = end_time
            dataframe_data['Live Time Duration'] = live_time_duration_str
            all_columns = list(dataframe_data.columns)
            st.sidebar.header("P1ease Filter Here:")
            # st.sidebar.divider()
            # Filter reset button
            if st.sidebar.button("Reset Filters"):
                st.experimental_rerun()
            # Multiselect for filtering by protocol
            selected_protocols = st.sidebar.multiselect(
                "Select Protocol:",
                options=dataframe_data["Procotol"].unique(), default=None
            )
            # st.sidebar.divider()

            # Sidebar slider for filtering by length
            filter_value_len = st.sidebar.slider(
                "Filter by Numeric Column",
                min_value=min(dataframe_data["len"]),
                max_value=max(dataframe_data["len"]),
                value=(min(dataframe_data["len"]), max(dataframe_data["len"]))
            )
            # st.sidebar.divider()

            # Sidebar text input for filtering by Source
            filter_source = st.sidebar.text_input("Filter by Source:", "")
            # st.sidebar.divider()

            # Sidebar text input for filtering by Destination
            filter_destination = st.sidebar.text_input("Filter by Destination:", "")
            # st.sidebar.divider()

            # Apply filters based on user selection
            if (
                    selected_protocols is None or not selected_protocols) and not filter_value_len and not filter_source and not filter_destination:
                st.write("All PCAPs:")
                Data_to_display_df = dataframe_data.copy()
                st.dataframe(Data_to_display_df, use_container_width=True)

            else:
                # Apply filters based on user input

                # Filter by protocol
                if selected_protocols is not None and selected_protocols:
                    Data_to_display_df = dataframe_data[dataframe_data["Procotol"].isin(selected_protocols)]
                else:
                    Data_to_display_df = dataframe_data

                # Filter by length
                Data_to_display_df = Data_to_display_df[
                    (Data_to_display_df["len"] >= filter_value_len[0]) & (
                            Data_to_display_df["len"] <= filter_value_len[1])
                    ]

                # Filter by Source
                if filter_source:
                    Data_to_display_df = Data_to_display_df[
                        Data_to_display_df["Source"].str.contains(filter_source, case=False, na=False)]

                # Filter by Destination
                if filter_destination:
                    Data_to_display_df = Data_to_display_df[
                        Data_to_display_df["Destination"].str.contains(filter_destination, case=False, na=False)]

                # Display the filtered dataframe
                st.write("Filtered PCAPs:")

                column_check = st.checkbox("Do you want to filter the data by column wise also ???")
                if column_check:
                    # Multiselect for filtering by columns
                    selected_columns = st.multiselect(
                        "Select Columns to Display:",
                        options=all_columns, default=all_columns
                    )
                    Data_to_display_df = Data_to_display_df[selected_columns]
                # selected_columns = [col for col in Data_to_display_df.columns if st.checkbox(col, value=True )]
                st.checkbox("Use container width", value=True, key="use_container_width")
                st.dataframe(Data_to_display_df, use_container_width=st.session_state.use_container_width)

                st.subheader("Statistics of Selected Data")
                # Time Analysis
                Data_to_display_df['time'] = pd.to_datetime(Data_to_display_df['time'])
                st.subheader("Time Range:")
                st.write("Earliest timestamp:", Data_to_display_df['time'].min())
                st.write("Latest timestamp:", Data_to_display_df['time'].max())
                st.write("Duration:", Data_to_display_df['time'].max() - Data_to_display_df['time'].min())
                ####################################
                col1, col2 = st.columns(2)

                # Column 1: Packet Length Statistics
                with col1:
                    st.subheader("Packet Length Statistics:")
                    st.table(Data_to_display_df['len'].describe())

                    # Source Counts
                    source_counts = Data_to_display_df['Source'].value_counts()
                    st.subheader("Source Counts:")
                    st.table(source_counts)

                # Column 2: Protocol Distribution and Destination Counts
                with col2:
                    # Protocol Distribution
                    protocol_counts = Data_to_display_df['Procotol'].value_counts(normalize=True)
                    st.subheader("Protocol Distribution:")
                    st.table(protocol_counts)

                    # Destination Counts
                    destination_counts = Data_to_display_df['Destination'].value_counts()
                    st.subheader("Destination Counts:")
                    st.table(destination_counts)



                #####################################






        else:
            st.warning("Please upload a valid PCAP file.")



def DataPacketLengthStatistics(data):
    # st.write("Data Packet Length Statistics")
    data1 = {'pcap_len': list(data.keys()), 'count': list(data.values())}
    df1 = pd.DataFrame(data1)

    options = {
        "title": {"text": "Data Packet Length Statistics", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Packets",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df1['pcap_len'], df1['count'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }

    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')


def CommonProtocolStatistics(data):
    st.write("Common Protocol Statistics")
    data2 = {'protocol_type': list(data.keys()),
             'number_of_packets': list(data.values())}
    df2 = pd.DataFrame(data2)
    # plost.bar_chart(data=df2, bar='protocol_type', value='number_of_packets')

    options = {
        "xAxis": {
            "type": "category",
            "data": df2.protocol_type.tolist(),
        },
        "yAxis": {"type": "value"},
        "series": [{"data": df2.number_of_packets.tolist(), "type": "bar"}],
    }
    st_echarts(options=options, height="500px")

def CommonProtocolStatistics_ploty(data):
    # st.write('Common Protocol Statistics')
    data2 = {'protocol_type': list(data.keys()),
             'number_of_packets': list(data.values())}
    df2 = pd.DataFrame(data2)
    fig = px.bar(df2, x='protocol_type', y='number_of_packets',color="protocol_type",title="Common Protocol Statistics")
    fig.update_layout(title_x=0.5)

    st.plotly_chart(fig)




def MostFrequentProtocolStatistics(data):
    # st.write("Data Packet Length Statistics")
    data3 = {'protocol_type': list(data.keys()), 'freq': list(data.values())}
    df3 = pd.DataFrame(data3)

    options = {
        "title": {"text": "Most Frequent Protocol Statistics", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Packets",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df3['protocol_type'], df3['freq'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }


    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')


def HTTP_HTTPSAccessStatistics(key,value):
    # st.write("HTTP/HTTPS Access Statistics")
    data4 = {'HTTP/HTTPS key': list(key),
             'HTTP/HTTPS value': list(value)}
    df4 = pd.DataFrame(data4)
    fig = px.bar(df4, x='HTTP/HTTPS key', y='HTTP/HTTPS value',color="HTTP/HTTPS key",title="HTTP/HTTPS Access Statistics")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)



def DNSAccessStatistics(key, value):
    # st.write("DNS Access Statistics")
    data5 = {'dns_key': list(key),
             'dns_value': list(value)}
    df5 = pd.DataFrame(data5)
    fig = px.bar(df5, x='dns_key', y='dns_value', color="dns_key",title="DNS Access Statistics")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)


def TimeFlowChart(data):
    data6 = {'Relative_Time': list(data.keys()), 'Packet_Bytes': list(data.values())}
    df6 = pd.DataFrame(data6)
    fig = px.line(df6, x='Relative_Time', y="Packet_Bytes",title="Time Flow Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)
def DataInOutStatistics(data):
    # st.write("Data In/Out Statistics")
    data7 = {'In/Out': list(data.keys()), 'freq': list(data.values())}
    df7 = pd.DataFrame(data7)

    options = {
        "title": {"text": "Data In/Out Statistics", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Data ",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df7['In/Out'], df7['freq'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }

    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')

def TotalProtocolPacketFlow(data):
    # st.write("Total Protocol Packet Flow bar chart")
    data8 = {'Protocol': list(data.keys()), 'freq': list(data.values())}
    df8 = pd.DataFrame(data8)

    options = {
        "title": {"text": "Total Protocol PacketFlow", "subtext": "", "left": "center"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "Protocols",
                "type": "pie",
                "radius": "50%",
                "data": [
                    {"value": count, "name": pcap_len}
                    for pcap_len, count in zip(df8['Protocol'], df8['freq'])
                ],
                "emphasis": {
                    "itemStyle": {
                        "shadowBlur": 10,
                        "shadowOffsetX": 0,
                        "shadowColor": "rgba(0, 0, 0, 0.5)",
                    }
                },
            }
        ],
        "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    }

    # st.write("Data Packet Length Statistics")
    st_echarts(options=options, height="600px", renderer='svg')

def TotalProtocolPacketFlowbarchart(data):
    # st.write("Total Protocol Packet Flow bar chart")
    data9 = {'Protocol': list(data.keys()), 'freq': list(data.values())}
    df9 = pd.DataFrame(data9)
    fig = px.bar(df9, x='Protocol', y='freq', color="Protocol",title="Total Protocol Packet Flow bar chart")
    fig.update_layout(title_x=0.5)

    st.plotly_chart(fig)


def InboundIPTrafficDataPacketCountChart(data):
    # st.write("Inbound IP Traffic Data Packet Count Chart")
    data10 = {'Inbound IP': list(data['in_keyp']), 'Number of Data Packets': list(data['in_packet'])}
    df10 = pd.DataFrame(data10)
    fig = px.bar(df10, x='Inbound IP', y='Number of Data Packets', color="Inbound IP",title="Inbound IP Traffic Data Packet Count Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)

def InboundIPTotalTrafficChart(data):
    # st.write("Inbound IP Total Traffic Chart")
    data11 = {'Inbound IP': list(data['in_keyl']), 'Total Data Packet Traffic': list(data['in_len'])}
    df11 = pd.DataFrame(data11)
    fig = px.bar(df11, x='Inbound IP', y='Total Data Packet Traffic', color="Inbound IP",title="Inbound IP Total Traffic Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)

def OutboundIPTrafficDataPacketCountChart(data):  # ip_flow['out_keyp'], ip_flow['out_packet']
    # st.write("Outbound IP Traffic Data Packet Count Chart")
    data12 = {'Outbound IP': list(data['out_keyp']), 'Number of Data Packets': list(data['out_packet'])}
    df12 = pd.DataFrame(data12)
    fig = px.bar(df12, x='Outbound IP', y='Number of Data Packets', color="Outbound IP",title="Outbound IP Traffic Data Packet Count Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)
def OutboundIPTotalTrafficChart(data):  # ip_flow['out_keyl'],ip_flow['out_len']
    st.write("Outbound IP Total Traffic Chart")
    data13 = {'Outbound IP': list(data['out_keyl']), 'Total Data Packet Traffic': list(data['out_len'])}
    df13 = pd.DataFrame(data13)
    fig = px.bar(df13, x='Outbound IP', y='Total Data Packet Traffic', color="Outbound IP",title="Outbound IP Total Traffic Chart")
    fig.update_layout(title_x=0.5)
    st.plotly_chart(fig)


def DrawFoliumMap(data):
    m = folium.Map(location=[data.iloc[0]['Coordinates'][1], data.iloc[0]['Coordinates'][0]],
                   zoom_start=5)

    # Create MarkerCluster layer
    marker_cluster = MarkerCluster().add_to(m)

    # Add markers for each location in the DataFrame
    for index, row in data.iterrows():
        popup_text = f"IP Address: {row['IP_Address']}<br>Data Traffic: {row['Data_Traffic']}"

        folium.Marker(
            location=row['Coordinates'][::-1],
            popup=folium.Popup(popup_text, max_width=300),
            icon=folium.Icon(color='blue'),  # Customize marker color
        ).add_to(marker_cluster)

    # Display the map in Streamlit
    folium_static(m,width=1820 , height=600)

def main():
    st.set_page_config(page_title="PCAP Dashboard", page_icon="📈", layout="wide")
    # download from Bootstrap
    selected = option_menu(
        menu_title=None,
        options=["Home", "Upload File", "Raw Data & Filtering", "Analysis","Geoplots"],
        icons=["house", "upload", "files", "graph-up","globe"],
        menu_icon="cast",
        default_index=0,
        orientation="horizontal"
    )

    # Intro Page
    if selected == "Home":
        # Page header
        st.subheader("Understanding PCAP Files in Cybersecurity")
        Intro()

    # File uploader
    if selected == "Upload File":
        page_file_upload()
        page_display_info()

    # Raw Data Visualizer and Filtering
    if selected == "Raw Data & Filtering":
        st.subheader("Raw Data Can be Visualized Here")
        RawDataView()

    if selected == "Analysis":
        st.subheader("Dashboard")
        if "pcap_data" not in st.session_state:
            st.session_state.pcap_data = []
        # get analysis of data
        else:
            data_of_pcap = st.session_state.pcap_data
            if data_of_pcap is None:
                art = """
                .....+@*+@+..................................................*@+*@+.....
                ....%-....:*................................................*:....:@....
                .:%%*.....:*................................................*:.....*%%:.
                +=.......:@..................................................@-.......-*
                %..........*#..............................................#*..........%
                =*...-%:.....#+...................::::...................+%.....:%-..:#=
                ..:=-..+#:....:%=..........-*%%#+======+*#%#=:.........=%:....:#...-=:..
                .........*#.....-%-.....+%*==================+#%-....-%-.....#*.........
                ...........#*.....=%:-%*=========================#*-%=.....*#...........
                .............%+....-%+=============================#*....+%.............
                ..............:%=.#*=================================@-=%:..............
                ................=@====================================##................
                ................%===+*##%%%%%%%%%%%%%%%%%%%%%%%%###+===*=...............
                ...............@%%%####%%%%%@@@@@@@@@@@@@@@@%%%%%%###%%%@-..............
                ..........:+##%@%#*++++==========================++++*#%@@##*:..........
                .....*%@*+==========+#%%%%%@@%##**+++++**#%%@%%%%%%*==========+*%%*.....
                ...%+=========#@+::...................................:-%%=========+%...
                ...*%========*+........#@@@@%*............=%@@@@%:.......-@========%#...
                ......#@@#===*+.....=@@@@@@@@@@@........*@@@@@@@@@@+.....:@===#@@#:.....
                .............**....*@@@@@@@@@@@@@:.....%@@@@@@@@@@@@#....-@:............
                ..............%....@@@@@@@@@@@@@@@....=@@@@@@@@@@@@@@-...+=.............
                ..............*-...@@@@@@@@@@@@@@@....*@@@@@@@@@@@@@@-...%..............
                ...............@...#@@@@@@@@@@@@@=....:@@@@@@@@@@@@@@...#=..............
                ...............:%...%@@@@@@@@@@@*......=@@@@@@@@@@@@:..-+...............
                ................:#...:%@@@@@@@#....--....*@@@@@@@@=...+#................
                .................:%:.............+@@@@=..............#=.................
                ..................-%#............+@@@@=............=@=..................
                ................-%-..**:...........--............+#:.-%-................
                ..............:%=.....+%%+:...................=%%*.....=%:..............
                .............#+.....=%:..%=+%*=:.........=+%*-@..:%+.....+%.............
                ...........**.....-%-...:#*...%=:==**+=-=%...#+#...:%=.....*#...........
                .........+#:....-%-.....*@.:**#....-:....%**-.%@.....-%:.....#+.........
                ..:=-..=#:....:%=.......=*%..%.:-=+**+==:.%..%*@.......=%:....:#=..:-:..
                =#:..-%:.....#*..........@.=@*.....-:.....*%*.#:.........+#.....:%=..:#=
                %..........*#............=%...=#%*+++=*#%+:..*#............#*..........%
                *=.......:@...............-@:...............%+..............:@:.......-*
                .:%%*.....:*................##............*%:...............*:.....*#%:.
                ....%:....:*..................:%@#=::-*%@=..................*:....:@....
                .....+@++%*..................................................*%++@+.....
                """

                st.code(art)
            else:
                data_len_stats = pcap_len_statistic(data_of_pcap)  # protocol len statistics
                data_protocol_stats = common_proto_statistic(data_of_pcap)  # count the occurrences of common network protocols
                data_count_dict = most_proto_statistic(data_of_pcap,
                                                       PD)  # counts the occurrences of each protocol and returns most common 10 protocols.
                http_key, http_value = https_stats_main(data_of_pcap)  # https Protocol Statistics
                dns_key, dns_value = dns_stats_main(data_of_pcap)  # DNS Protocol Statistics
                # Data Protocol analysis end

                # Traffic analysis start
                time_flow_dict = time_flow(data_of_pcap)
                host_ip = get_host_ip(data_of_pcap)
                data_flow_dict = data_flow(data_of_pcap, host_ip)
                data_ip_dict = data_in_out_ip(data_of_pcap, host_ip)
                proto_flow_dict = proto_flow(data_of_pcap)
                most_flow_dict = most_flow_statistic(data_of_pcap, PD)
                most_flow_dict = sorted(most_flow_dict.items(), key=lambda d: d[1], reverse=True)
                if len(most_flow_dict) > 10:
                    most_flow_dict = most_flow_dict[0:10]
                most_flow_key = list()
                for key, value in most_flow_dict:
                    most_flow_key.append(key)
                # Traffic analysis end

                # ///////////////////////////////////////////
                # ////     Data of Protocol Analysis    /////
                # ///////////////////////////////////////////
                # DataPacketLengthStatistics(data_len_stats)  #Piechart
                # # CommonProtocolStatistics(data_protocol_stats)
                # CommonProtocolStatistics_ploty(data_protocol_stats) #Barchart
                # MostFrequentProtocolStatistics(data_count_dict) #Piechart
                # HTTP_HTTPSAccessStatistics(http_key,http_value)  #Bar CHart axis -90
                # DNSAccessStatistics(dns_key,dns_value) #BarChart axis -90
                # col1, col2 = st.columns([2, 3])
                #
                # # Column 1: DataPacketLengthStatistics - Piechart
                # with col1:
                #     st.subheader("Data Packet Length Statistics")
                #     DataPacketLengthStatistics(data_len_stats)
                #
                #     # MostFrequentProtocolStatistics - Piechart
                #     st.subheader("Most Frequent Protocol Statistics")
                #     MostFrequentProtocolStatistics(data_count_dict)
                #
                # # Column 2: CommonProtocolStatistics_plotly - Barchart
                # with col2:
                #     st.subheader("Common Protocol Statistics")
                #     CommonProtocolStatistics_ploty(data_protocol_stats)
                #
                #     # HTTP_HTTPSAccessStatistics - BarChart axis -90
                #     st.subheader("HTTP/HTTPS Access Statistics")
                #     HTTP_HTTPSAccessStatistics(http_key, http_value)
                #
                #     # DNSAccessStatistics - BarChart axis -90
                #     st.subheader("DNS Access Statistics")
                #     DNSAccessStatistics(dns_key, dns_value)

                st.title(" Data of Protocol Analysis  ")
                # Create a 2x2 column layout
                col1, col2 = st.columns(2)

                # Column 1: Uneven row heights
                with col1:
                    # Row 1
                    with st.expander("Data Packet Length Statistics"):
                        DataPacketLengthStatistics(data_len_stats)

                    # Row 2 (smaller height)
                    with st.expander("Most Frequent Protocol Statistics"):
                        MostFrequentProtocolStatistics(data_count_dict)


                # Column 2: Uneven row heights
                with col2:
                    # Row 1
                    with st.expander("Common Protocol Statistics"):
                        CommonProtocolStatistics_ploty(data_protocol_stats)

                    # Row 2 (larger height)
                    with st.expander("HTTP/HTTPS Access Statistics Details"):
                        HTTP_HTTPSAccessStatistics(http_key, http_value)

                    # Row 3 (smaller height)
                    with st.expander("DNS Access Statistics"):
                        DNSAccessStatistics(dns_key, dns_value)

                # ///////////////////////////////////////////
                # ////     Data of Traffic Analysis     /////
                # ///////////////////////////////////////////
                st.title("Data of Traffic Analysis")
                col3, col4 = st.columns(2)
                with col3:
                    # Row 1
                    with st.expander("Time Flow Chart"):
                        TimeFlowChart(time_flow_dict)

                    # Row 2 (smaller height)
                    with st.expander("Data In/Out Statistics"):
                        DataInOutStatistics(data_flow_dict)



                # Column 2: Uneven row heights
                with col4:
                    # Row 1
                    with st.expander("Total Protocol Packet Flow"):
                        TotalProtocolPacketFlow(proto_flow_dict)


                    # Row 2 (larger height)
                    with st.expander("Total Protocol Packet Flow bar chart"):
                        TotalProtocolPacketFlowbarchart(proto_flow_dict)




                # Inbound /Outbound


                st.title("Inbound /Outbound ")
                col5, col6 = st.columns(2)
                with col5:
                    # Row 1
                    with st.expander("Inbound IP Traffic Data Packet Count Chart"):
                        InboundIPTrafficDataPacketCountChart(data_ip_dict)  #Bar CHart axis -90 #ip_flow['in_keyp'], ip_flow['in_packet']

                    # Row 2 (smaller height)
                    with st.expander("Inbound IP Total Traffic Chart"):
                        InboundIPTotalTrafficChart(data_ip_dict)  #Bar CHart axis -90 #ip_flow['in_keyl'],ip_flow['in_len']

                # Column 2: Uneven row heights
                with col6:
                    # Row 1
                    with st.expander("Outbound IP Traffic Data Packet Count Chart"):
                        OutboundIPTrafficDataPacketCountChart(data_ip_dict)  #Bar CHart axis -90 # ip_flow['out_keyp'], ip_flow['out_packet']

                    # Row 2 (larger height)
                    with st.expander("Outbound IP Total Traffic Chart"):
                        OutboundIPTotalTrafficChart(data_ip_dict)   #Bar CHart axis -90 # ip_flow['out_keyl'],ip_flow['out_len']




    if selected == "Geoplots":
        st.subheader("Geoplot")
        # ///////////////////////////////////////////
        # ////              Data of Geoplot     /////
        # ///////////////////////////////////////////
        if "pcap_data" not in st.session_state:
            st.session_state.pcap_data = []
            st.warning("No valid data for Geoplot.")
        else:
            data_of_pcap = st.session_state.pcap_data
            if data_of_pcap:
                ipmap_result = ipmap(data_of_pcap)
                # Display the map in Streamlit
                DrawFoliumMap(ipmap_result)
            else:
                st.warning("No valid data for Geoplot.")









if __name__ == "__main__":
    main()
