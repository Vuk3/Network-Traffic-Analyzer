import base64
import pyshark
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from tkcalendar import DateEntry
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from datetime import datetime

from extraction import *

canvas = None  # Globalna promenljiva za canvas
current_file_path = None  # Globalna promenljiva za trenutni fajl
all_packets = []  # Lista za sve pakete
fromApplyFilter = False

# Funkcija za čitanje pcap-ng fajla
def read_pcap(file_path):
    return pyshark.FileCapture(file_path)

def extract_all_protocols(packet):
    protocols = []
    for layer in packet.layers:
        protocols.append(layer.layer_name.upper())
    return ', '.join(protocols)

def reset_filters():
    current_date = datetime.now().date()
    start_date_entry.set_date(current_date)
    end_date_entry.set_date(current_date)

    start_time_entry.delete(0, tk.END)
    end_time_entry.delete(0, tk.END)

    source_ip_entry.delete(0, tk.END)
    dest_ip_entry.delete(0, tk.END)
    protocols_entry.delete(0, tk.END)

# Glavna funkcija za analizu pcap-ng fajla
def analyze_pcap(packets, start_date=None, end_date=None, source_ip="", destination_ip="", protocolsString=""):
    results = []
    protocol_counts = {}
    global fromApplyFilter

    for i, packet in enumerate(packets, start=1):
        if (fromApplyFilter == True):
            if start_date and packet.sniff_time < start_date:
                continue
            if end_date and packet.sniff_time > end_date:
                continue
            if hasattr(packet, 'ip'):
                if source_ip != "" and packet.ip.src != source_ip:
                    continue
                if destination_ip != "" and packet.ip.dst != destination_ip:
                    continue
            if protocolsString != "":
                protocolsList = protocolsString.split(',')
                protocols = extract_all_protocols(packet).split(', ')
                found = False
                for protocol in protocolsList:
                    if protocol in protocols:
                        found = True
                        break
                if not found:
                    continue
        packet_data = {}
        if 'HTTP' in packet:
            packet_data['HTTP'] = extract_http_data(packet)
        if 'SSL' in packet:
            packet_data['HTTPS'] = extract_https_data(packet)
        if 'DNS' in packet:
            packet_data['DNS'] = extract_dns_data(packet)
        if 'FTP' in packet:
            packet_data['FTP'] = extract_ftp_data(packet)
        if 'SMTP' in packet:
            packet_data['SMTP'] = extract_smtp_data(packet)
        if 'ARP' in packet:
            packet_data['ARP'] = extract_arp_data(packet)
        if 'ICMP' in packet:
            packet_data['ICMP'] = extract_icmp_data(packet)
        if 'IP' in packet:
            packet_data['IP'] = extract_ip_data(packet)
        if 'ETH' in packet:
            packet_data['Ethernet'] = extract_ethernet_data(packet)
        if 'TCP' in packet:
            packet_data['TCP'] = extract_tcp_data(packet)
        if 'UDP' in packet:
            packet_data['UDP'] = extract_udp_data(packet)
        if 'FPP' in packet:
            packet_data['FPP'] = extract_fpp_data(packet)

        protocols = extract_all_protocols(packet).split(', ')
        for proto in protocols:
            if proto not in protocol_counts:
                protocol_counts[proto] = 0
            protocol_counts[proto] += 1
        if packet_data:
            packet_info = {
                'Packet Number': f"Packet {i}",
                'Timestamp': packet.sniff_time,
                'Length': packet.length,
                'Source IP': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                'Destination IP': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                'Protocols': ', '.join(protocols),
                'Data': packet_data
            }
            results.append(packet_info)
    return results, protocol_counts

def visualize_data(protocol_counts, root):
    global canvas
    if canvas:
        canvas.get_tk_widget().pack_forget()

    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

    # Pie chart
    ax1.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=140, colors=plt.cm.Paired(range(len(protocols))))
    ax1.axis('equal')
    ax1.set_title('Protocol Distribution - Pie Chart')

    # Bar chart
    ax2.bar(protocols, counts, color='skyblue')
    ax2.set_xlabel('Protocol')
    ax2.set_ylabel('Count')
    ax2.set_title('Protocol Distribution - Bar Chart')

    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.draw()
    canvas.get_tk_widget().pack()

# GUI funkcije
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcapng *.pcap")])
    if file_path:
        analyze_and_display(file_path)

def analyze_and_display(file_path):
    global current_file_path, all_packets
    current_file_path = file_path  # Sačuvaj trenutni put do fajla
    capture = read_pcap(file_path)
    all_packets = [pkt for pkt in capture]  # Učitavanje svih paketa u listu
    capture.close()
    result_tree.delete(*result_tree.get_children())

    reset_filters()
    results, protocol_counts = analyze_pcap(all_packets)
    for result in results:
        timestamp = result['Timestamp'].strftime("%Y-%m-%d %H:%M:%S")
        source_ip = result['Source IP']
        destination_ip = result['Destination IP']
        length = result['Length']
        protocols = result['Protocols']

        packet_id = result_tree.insert("", "end", text=timestamp, values=(source_ip, destination_ip, length, protocols))

        for proto, data in result['Data'].items():
            proto_id = result_tree.insert(packet_id, "end", text=proto)
            for key, value in data.items():
                result_tree.insert(proto_id, "end", text=key, values=(value,))

    visualize_data(protocol_counts, root)  # Prikaz grafikona

def apply_filter():
    if current_file_path:
        global fromApplyFilter
        fromApplyFilter = True

        start_date_value = start_date_entry.get_date()
        end_date_value = end_date_entry.get_date()

        start_time_value = start_time_entry.get()
        end_time_value = end_time_entry.get()
        if not start_time_value or start_time_value == "":
            start_time_value = "00:00:00"
        if not end_time_value or end_time_value == "":
            end_time_value = "23:59:59"
        start_datetime = datetime.combine(start_date_value, datetime.strptime(start_time_value, "%H:%M:%S").time())
        end_datetime = datetime.combine(end_date_value, datetime.strptime(end_time_value, "%H:%M:%S").time())

        results, protocol_counts = analyze_pcap(all_packets, start_datetime, end_datetime, source_ip_entry.get(), dest_ip_entry.get(), protocols_entry.get())
        fromApplyFilter = False
        result_tree.delete(*result_tree.get_children())

        for result in results:
            timestamp = result['Timestamp'].strftime("%Y-%m-%d %H:%M:%S")
            source_ip = result['Source IP']
            destination_ip = result['Destination IP']
            length = result['Length']
            protocols = result['Protocols']

            packet_id = result_tree.insert("", "end", text=timestamp, values=(source_ip, destination_ip, length, protocols))

            for proto, data in result['Data'].items():
                proto_id = result_tree.insert(packet_id, "end", text=proto)
                for key, value in data.items():
                    result_tree.insert(proto_id, "end", text=key, values=(value,))

        visualize_data(protocol_counts, root)  # Prikaz grafikona

# Kreiranje GUI-ja
root = tk.Tk()
root.title("Network Traffic Analyzer")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10, fill=tk.X)

open_button = tk.Button(frame, text="Open PCAP File", command=open_file, bg='lightblue')
open_button.pack(pady=5)

filter_frame = tk.Frame(root)
filter_frame.pack(padx=10, pady=10, fill=tk.X)

start_date_label = tk.Label(filter_frame, text="Start Date")
start_date_label.grid(row=0, column=0)
start_date_entry = DateEntry(filter_frame, width=12, background='darkblue', foreground='white', borderwidth=2)
start_date_entry.grid(row=1, column=0, padx=5, pady=5)

end_date_label = tk.Label(filter_frame, text="End Date")
end_date_label.grid(row=0, column=1)
end_date_entry = DateEntry(filter_frame, width=12, background='darkblue', foreground='white', borderwidth=2)
end_date_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(filter_frame, text="Start Time:").grid(row=0, column=2, padx=10, pady=5)
start_time_entry = ttk.Entry(filter_frame)
start_time_entry.grid(row=0, column=3, padx=10, pady=5)

tk.Label(filter_frame, text="End Time:").grid(row=1, column=2, padx=10, pady=5)
end_time_entry = ttk.Entry(filter_frame)
end_time_entry.grid(row=1, column=3, padx=10, pady=5)

source_ip_label = tk.Label(filter_frame, text="Source IP Filter")
source_ip_label.grid(row=0, column=4)
source_ip_entry = tk.Entry(filter_frame)
source_ip_entry.grid(row=1, column=4, padx=5, pady=5)

dest_ip_label = tk.Label(filter_frame, text="Destination IP Filter")
dest_ip_label.grid(row=0, column=5)
dest_ip_entry = tk.Entry(filter_frame)
dest_ip_entry.grid(row=1, column=5, padx=5, pady=5)

protocols_label = tk.Label(filter_frame, text="Protocols Filter")
protocols_label.grid(row=0, column=6)
protocols_entry = tk.Entry(filter_frame)
protocols_entry.grid(row=1, column=6, padx=5, pady=5)

apply_button = tk.Button(filter_frame, text="Apply Filter", command=apply_filter, bg='lightgreen')
apply_button.grid(row=1, column=7, padx=5, pady=5)

result_frame = tk.Frame(root)
result_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

result_tree = ttk.Treeview(result_frame)
result_tree.pack(fill=tk.BOTH, expand=True)

result_tree["columns"] = ("Source IP", "Destination IP", "Length", "Protocols")
result_tree.heading("#0", text="Timestamp")
result_tree.heading("Source IP", text="Source IP")
result_tree.heading("Destination IP", text="Destination IP")
result_tree.heading("Length", text="Length")
result_tree.heading("Protocols", text="Protocols")

root.mainloop()