import scapy.all as scapy
import tkinter as tk
from tkinter import ttk, Menu, font as tkfont
import threading
import pyperclip

packet_counts = {}
packet_details = {}
is_adding_packets = False
sniff_thread_started = False

protocol_map = {
    6: 'TCP',
    17: 'UDP',
    1: 'ICMP',
    2: 'IGMP',
    4: 'IPv4',
    41: 'IPv6',
    89: 'OSPF'
}

def copy_to_clipboard(text):
    pyperclip.copy(text)

def packet_callback(packet):
    global is_adding_packets

    if not is_adding_packets:
        return

    if packet.haslayer(scapy.IP):
        src = packet[scapy.IP].src
        dst = packet[scapy.IP].dst
        proto = packet[scapy.IP].proto

        proto_name = protocol_map.get(proto, str(proto))

        if packet.haslayer(scapy.TCP):
            src += ':' + str(packet[scapy.TCP].sport)
            dst += ':' + str(packet[scapy.TCP].dport)
        elif packet.haslayer(scapy.UDP):
            src += ':' + str(packet[scapy.UDP].sport)
            dst += ':' + str(packet[scapy.UDP].dport)

        packet_key = (src, dst, proto_name)
        packet_id = len(packet_details)
        packet_details[packet_id] = packet
        packet_counts[packet_key] = (packet_counts.get(packet_key, (0, None))[0] + 1, packet_id)

def toggle_packet_adding():
    global is_adding_packets, sniff_thread_started

    is_adding_packets = not is_adding_packets
    start_button.config(text="Arrêter la Capture" if is_adding_packets else "Démarrer la Capture")

    if not sniff_thread_started:
        sniff_thread_started = True
        threading.Thread(target=lambda: scapy.sniff(prn=packet_callback, store=False)).start()
        schedule_update()

def update_tree():
    try:
        packet_counts_copy = dict(packet_counts)
        for i in tree.get_children():
            tree.delete(i)
        for packet_key, (count, packet_id) in packet_counts_copy.items():
            src, dst, proto = packet_key
            tree.insert("", 'end', values=(count, src, dst, proto, packet_id))
    except RuntimeError:
        packet_counts.clear()
        update_tree()

def schedule_update():
    if is_adding_packets:
        try:
            update_tree()
        except Exception as e:
            print(f"Une erreur s'est produite: {e}")
        finally:
            app.after(1000, schedule_update)

def show_packet_details():
    selected_item = tree.focus()
    if selected_item:
        packet_id = tree.item(selected_item, 'values')[4]
        packet = packet_details.get(int(packet_id))
        if packet:
            details_window = tk.Toplevel(app)
            details_window.title("Détails du paquet")
            details_text = tk.Text(details_window)
            details_text.insert(tk.END, packet.show(dump=True))
            details_text.pack(expand=True, fill='both')

def treeview_sort_column(tree, col, reverse):
    l = [(tree.set(k, col), k) for k in tree.get_children('')]
    l.sort(reverse=reverse)

    for index, (val, k) in enumerate(l):
        tree.move(k, '', index)

    tree.heading(col, command=lambda: treeview_sort_column(tree, col, not reverse))

def copy_source_ip_port():
    selected_item = tree.focus()
    if selected_item:
        source_ip_port = tree.item(selected_item, 'values')[1]
        copy_to_clipboard(source_ip_port)

def copy_destination_ip_port():
    selected_item = tree.focus()
    if selected_item:
        destination_ip_port = tree.item(selected_item, 'values')[2]
        copy_to_clipboard(destination_ip_port)

def copy_protocol():
    selected_item = tree.focus()
    if selected_item:
        protocol = tree.item(selected_item, 'values')[3]
        copy_to_clipboard(protocol)

app = tk.Tk()
app.title("Yoshi Packet Sniffer")

columns = ("Count", "Source IP:Port", "Destination IP:Port", "Protocol", "Packet ID")
tree = ttk.Treeview(app, columns=columns, show='headings')

for col in columns:
    tree.heading(col, text=col, command=lambda _col=col: treeview_sort_column(tree, _col, False))
    tree.column(col, width=tkfont.Font().measure(col.title()))

tree.pack(expand=True, fill='both')

menu = Menu(app, tearoff=0)

def on_right_click(event):
    iid = tree.identify_row(event.y)
    if iid:
        tree.selection_set(iid)
        menu.delete(0, tk.END)
        menu.add_command(label="Copier Source IP:Port", command=copy_source_ip_port)
        menu.add_command(label="Copier Destination IP:Port", command=copy_destination_ip_port)
        menu.add_command(label="Copier Protocol", command=copy_protocol)
        menu.add_command(label="Visualiser les détails", command=show_packet_details)
        menu.post(event.x_root, event.y_root)

tree.bind("<Button-3>", on_right_click)

start_button = tk.Button(app, text="Démarrer la Capture", command=toggle_packet_adding)
start_button.pack(pady=20)

app.mainloop()
