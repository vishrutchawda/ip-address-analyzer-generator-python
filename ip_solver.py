from tkinter import *
from tkinter import messagebox, ttk
import time

def validate_ip(ip_str):
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False, None, "Invalid IP address. Must have exactly 4 parts."
    binary_count = sum(1 for part in parts if set(part) <= {'0', '1'} and len(part) == 8)
    if binary_count not in (0, 4):
        return False, None, "Invalid IP address. Do not mix binary and decimal representations."
    mode = "binary" if binary_count == 4 else "decimal"
    if mode == "decimal":
        for part in parts:
            if part.startswith("0") and len(part) > 1:
                return False, None, "Invalid IP address. It cannot contain leading zeros."
            if not part.isdigit():
                return False, None, "Invalid IP address. Each part must be a number."
            num = int(part)
            if num < 0 or num > 255:
                return False, None, "Invalid IP address. Each part must be between 0 and 255."
    else:
        for part in parts:
            if len(part) != 8 or not all(c in '01' for c in part):
                return False, None, "Invalid IP address. Each binary part must be exactly 8 bits of 0s and 1s."
    return True, mode, None

def is_private_ip(ip_parts):
    parts = [int(p) for p in ip_parts]
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    return False

def ip_to_binary(ip_parts, mode):
    if mode == "decimal":
        return ".".join(format(int(part), '08b') for part in ip_parts)
    else:
        return ".".join(str(int(part, 2)) for part in ip_parts)

def analyze_classfull(ip_address, mode):
    parts = ip_address.split(".")
    classs = None
    netbit = None
    hostbit = None
    subnetmask = None
    noofnet = None
    noofhost = None
    networkip = ""
    broadcastip = ""
    special = None
    class_desc = ""
    if mode == "binary":
        if parts[0].startswith("1111"):
            classs = "e"
            special = "It is reserved so the concept of network id bit and host id bit is not followed here."
            class_desc = "Class E :-  Reserved for experimental use."
        elif parts[0].startswith("1110"):
            classs = "d"
            special = "It is used for multicast so the concept of network id bit and host id bit is not followed here."
            class_desc = "Class D :-  Used for multicast applications."
        elif parts[0].startswith("110"):
            classs = "c"
            netbit = 24
            hostbit = 8
            subnetmask = "11111111.11111111.11111111.00000000"
            noofnet = "2 ^ 21"
            noofhost = f"2 ^ 8 approx , actual: {2**8 - 2}"
            parts_copy = parts[:]
            parts_copy[3] = "00000000"
            networkip = ".".join(parts_copy)
            parts_copy[3] = "11111111"
            broadcastip = ".".join(parts_copy)
            class_desc = "Class C :-  Used for small networks."
        elif parts[0].startswith("10"):
            classs = "b"
            netbit = 16
            hostbit = 16
            subnetmask = "11111111.11111111.00000000.00000000"
            noofnet = "2 ^ 14"
            noofhost = f"2 ^ 16 approx , actual: {2**16 - 2}"
            parts_copy = parts[:]
            parts_copy[2] = parts_copy[3] = "00000000"
            networkip = ".".join(parts_copy)
            parts_copy[2] = parts_copy[3] = "11111111"
            broadcastip = ".".join(parts_copy)
            class_desc = "Class B :-  Used for medium-sized networks."
        elif parts[0].startswith("0"):
            classs = "a"
            netbit = 8
            hostbit = 24
            subnetmask = "11111111.00000000.00000000.00000000"
            noofnet = "2 ^ 7"
            noofhost = f"2 ^ 24 approx , actual: {2**24 - 2}"
            parts_copy = parts[:]
            parts_copy[1] = parts_copy[2] = parts_copy[3] = "00000000"
            networkip = ".".join(parts_copy)
            parts_copy[1] = parts_copy[2] = parts_copy[3] = "11111111"
            broadcastip = ".".join(parts_copy)
            class_desc = "Class A :-  Used for large networks."
    else:
        first_octet = int(parts[0])
        if 0 <= first_octet <= 127:
            classs = "a"
            netbit = 8
            hostbit = 24
            subnetmask = "255.0.0.0"
            noofnet = "2 ^ 7"
            noofhost = f"2 ^ 24 approx , actual: {2**24 - 2}"
            parts_copy = parts[:]
            parts_copy[1] = parts_copy[2] = parts_copy[3] = "0"
            networkip = ".".join(parts_copy)
            parts_copy[1] = parts_copy[2] = parts_copy[3] = "255"
            broadcastip = ".".join(parts_copy)
            class_desc = "Class A :-  Used for large networks."
        elif 128 <= first_octet <= 191:
            classs = "b"
            netbit = 16
            hostbit = 16
            subnetmask = "255.255.0.0"
            noofnet = "2 ^ 14"
            noofhost = f"2 ^ 16 approx , actual: {2**16 - 2}"
            parts_copy = parts[:]
            parts_copy[2] = parts_copy[3] = "0"
            networkip = ".".join(parts_copy)
            parts_copy[2] = parts_copy[3] = "255"
            broadcastip = ".".join(parts_copy)
            class_desc = "Class B :-  Used for medium-sized networks."
        elif 192 <= first_octet <= 223:
            classs = "c"
            netbit = 24
            hostbit = 8
            subnetmask = "255.255.255.0"
            noofnet = "2 ^ 21"
            noofhost = f"2 ^ 8 approx , actual: {2**8 - 2}"
            parts_copy = parts[:]
            parts_copy[3] = "0"
            networkip = ".".join(parts_copy)
            parts_copy[3] = "255"
            broadcastip = ".".join(parts_copy)
            class_desc = "Class C :-  Used for small networks."
        elif 224 <= first_octet <= 239:
            classs = "d"
            special = "It is used for multicast so the concept of network id bit and host id bit is not followed here."
            class_desc = "Class D :-  Used for multicast applications."
        elif 240 <= first_octet <= 255:
            classs = "e"
            special = "It is reserved so the concept of network id bit and host id bit is not followed here."
            class_desc = "Class E :-  Reserved for experimental use."
    result = f"Class :-  {classs}\n\n"
    result += f"Description :-  {class_desc}\n\n"
    ip_type = "Private" if is_private_ip(parts) else "Public"
    result += f"IP Type :-  {ip_type}\n\n"
    conv_ip = ip_to_binary(parts, mode)
    result += f"IP in {'Binary' if mode == 'decimal' else 'Decimal'} :-  {conv_ip}\n\n"
    if special:
        result += special + "\n\n"
    else:
        result += f"Network id bit :-  {netbit}\n\n"
        result += f"Host id bit :-  {hostbit}\n\n"
        result += f"Subnet mask :-  {subnetmask}\n\n"
        result += f"Network IP :-  {networkip}\n\n"
        result += f"Broadcast IP :-  {broadcastip}\n\n"
        result += f"No. of networks :-  {noofnet}\n\n"
        result += f"No. of host per network :-  {noofhost}\n\n"
    return result

def calculate_ip_range(network_ip, broadcast_ip, mode):
    if mode == "decimal":
        net_parts = [int(p) for p in network_ip.split(".")]
        broad_parts = [int(p) for p in broadcast_ip.split(".")]
        first_usable = net_parts[:]
        last_usable = broad_parts[:]
        if net_parts != broad_parts:
            first_usable[3] += 1
            last_usable[3] -= 1
        first_ip = ".".join(map(str, first_usable))
        last_ip = ".".join(map(str, last_usable))
    else:
        net_parts = network_ip.split(".")
        broad_parts = broadcast_ip.split(".")
        first_usable = net_parts[:]
        last_usable = broad_parts[:]
        if net_parts != broad_parts:
            first_usable[3] = format(int(net_parts[3], 2) + 1, '08b')
            last_usable[3] = format(int(broad_parts[3], 2) - 1, '08b')
        first_ip = ".".join(first_usable)
        last_ip = ".".join(last_usable)
    return first_ip, last_ip

def analyze_classless(ip_address, mode, netbit):
    parts = ip_address.split(".")
    result = f"Network ID bit :-  {netbit}\n\n"
    result += f"Host ID bit :-  {32 - netbit}\n\n"
    subnet = ['1'] * netbit + ['0'] * (32 - netbit)
    subnetmask_bin = '.'.join([''.join(subnet[i:i+8]) for i in range(0, 32, 8)])
    subnetmask_dec = '.'.join(str(int(part, 2)) for part in subnetmask_bin.split('.'))
    result += f"Subnet Mask in binary :-  {subnetmask_bin}\n\n"
    result += f"Subnet Mask in decimal :-  {subnetmask_dec}\n\n"
    if mode == "binary":
        networkip = []
        broadcastip = []
        for i in range(4):
            part_bin = parts[i]
            mask_bin = subnetmask_bin.split('.')[i]
            network_part = ''.join([p if m == '1' else '0' for p, m in zip(part_bin, mask_bin)])
            broadcast_part = ''.join([p if m == '1' else '1' for p, m in zip(part_bin, mask_bin)])
            networkip.append(network_part)
            broadcastip.append(broadcast_part)
        networkip_str = '.'.join(networkip)
        broadcastip_str = '.'.join(broadcastip)
    else:
        subnet_parts = [int(p) for p in subnetmask_dec.split('.')]
        ip_parts = [int(p) for p in parts]
        networkip = [ip & mask for ip, mask in zip(ip_parts, subnet_parts)]
        broadcastip = [ip | (255 - mask) for ip, mask in zip(ip_parts, subnet_parts)]
        networkip_str = '.'.join(map(str, networkip))
        broadcastip_str = '.'.join(map(str, broadcastip))
    result += f"Network IP :-  {networkip_str}\n\n"
    result += f"Broadcast IP :-  {broadcastip_str}\n\n"
    first_ip, last_ip = calculate_ip_range(networkip_str, broadcastip_str, mode)
    result += f"Usable IP Range :-  {first_ip} - {last_ip}\n\n"
    noofhost = f"2 ^ {32 - netbit} approx , actual: {2**(32 - netbit) - 2}"
    result += f"No. of host per network :-  {noofhost}\n\n"
    if mode == "binary":
        first_part = int(parts[0], 2)
    else:
        first_part = int(parts[0])
    if 0 <= first_part <= 127:
        noofnetwork = f"2 ^ {netbit - 8}"
    elif 128 <= first_part <= 191:
        noofnetwork = f"2 ^ {netbit - 16}"
    elif 192 <= first_part <= 223:
        noofnetwork = f"2 ^ {netbit - 24}"
    else:
        noofnetwork = "N/A"
    result += f"No. of networks :-  {noofnetwork}\n\n"
    ip_type = "Private" if is_private_ip(parts) else "Public"
    result += f"IP Type :-  {ip_type}\n\n"
    conv_ip = ip_to_binary(parts, mode)
    result += f"IP in {'Binary' if mode == 'decimal' else 'Decimal'} :-  {conv_ip}\n\n"
    return result

def toggle_cidr():
    if analysis_type.get() == "classless":
        cidr_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")
    else:
        cidr_frame.grid_remove()

def get_classful_base(hosts, ip_category):
    if ip_category == "private":
        if hosts <= 254:
            return "C", [192, 168, 0, 0], 24
        elif hosts <= 65534:
            return "B", [172, 16, 0, 0], 16
        else:
            return "A", [10, 0, 0, 0], 8
    else:  # public
        if hosts <= 254:
            return "C", [198, 51, 100, 0], 24
        elif hosts <= 65534:
            return "B", [131, 107, 0, 0], 16
        else:
            return "A", [1, 0, 0, 0], 8

def calculate_prefix(hosts):
    for prefix in range(32, 0, -1):
        max_hosts = 2**(32 - prefix) - 2
        if max_hosts >= hosts:
            return prefix
    return None

def ip_to_int(ip):
    return sum(int(part) << (24 - 8 * i) for i, part in enumerate(ip.split('.')))

def int_to_ip(n):
    return '.'.join(str((n >> 8 * i) & 255) for i in range(3, -1, -1))

def calculate_num_networks_classful(hosts, ip_category):
    class_type, _, net_bits = get_classful_base(hosts, ip_category)
    total_available_ips = {
        "A": 2**24 if ip_category == "public" else 2**24,  # 1.0.0.0/8 or 10.0.0.0/8
        "B": 2**16 if ip_category == "public" else 2**20,  # 131.107.0.0/16 or 172.16.0.0/12
        "C": 2**8 if ip_category == "public" else 2**16   # 198.51.100.0/24 or 192.168.0.0/16
    }[class_type]
    hosts_per_network = 2**(32 - net_bits)
    num_networks = total_available_ips // hosts_per_network
    return num_networks, class_type

def calculate_num_networks_classless(hosts, ip_category):
    prefix = calculate_prefix(hosts)
    if prefix is None:
        return 0, None
    block_size = 2**(32 - prefix)
    if ip_category == "private":
        if hosts <= 254:  # Use 192.168.0.0/16 for small networks
            total_available_ips = 2**16  # 65,536 addresses
            base_ip = "192.168.0.0"
        elif hosts <= 1048574:  # Use 172.16.0.0/12 for medium networks
            total_available_ips = 2**20  # 1,048,576 addresses
            base_ip = "172.16.0.0"
        else:  # Use 10.0.0.0/8 for large networks
            total_available_ips = 2**24  # 16,777,216 addresses
            base_ip = "10.0.0.0"
    else:  # public
        if hosts <= 254:  # Use a Class C-like range for small networks
            total_available_ips = 2**8  # 256 addresses (e.g., 198.51.100.0/24)
            base_ip = "198.51.100.0"
        elif hosts <= 65534:  # Use a Class B-like range
            total_available_ips = 2**16  # 65,536 addresses (e.g., 131.107.0.0/16)
            base_ip = "131.107.0.0"
        else:  # Use a Class A-like range
            total_available_ips = 2**24  # 16,777,216 addresses (e.g., 1.0.0.0/8)
            base_ip = "1.0.0.0"
    num_networks = total_available_ips // block_size
    return num_networks, prefix, base_ip

def generate_classful(hosts, ip_category):
    if hosts > 16777214:
        return "Error: Too many hosts for classful addressing (max 16,777,214 for Class A)."
    num_networks, class_type = calculate_num_networks_classful(hosts, ip_category)
    if num_networks == 0:
        return "Error: Cannot allocate networks for the given number of hosts."
    class_type, base_ip, net_bits = get_classful_base(hosts, ip_category)
    networks = []
    current_ip = base_ip[:]
    max_display = 5  # Limit to first 5 networks
    if class_type == "C":
        for i in range(min(num_networks, max_display)):
            network_ip = ".".join(map(str, current_ip))
            networks.append(network_ip)
            current_ip[2] += 1
            if current_ip[2] > 255:
                current_ip[2] = 0
                current_ip[1] += 1
    elif class_type == "B":
        for i in range(min(num_networks, max_display)):
            network_ip = ".".join(map(str, current_ip))
            networks.append(network_ip)
            current_ip[1] += 1
            if ip_category == "private" and class_type == "B":
                if current_ip[1] > 31:
                    current_ip[1] = 16
                    current_ip[0] += 1
            else:
                if current_ip[1] > 255:
                    current_ip[1] = 0
                    current_ip[0] += 1
    elif class_type == "A":
        for i in range(min(num_networks, max_display)):
            network_ip = ".".join(map(str, current_ip))
            networks.append(network_ip)
            current_ip[0] += 1
    results = ""
    for net_ip in networks:
        details = analyze_classfull(net_ip, "decimal")
        results += f"Network {net_ip}:\n{details}\n\n"
    if num_networks > max_display:
        results += f"... and {num_networks - max_display} more networks can be created.\n"
    return results

def generate_classless(hosts, ip_category):
    num_networks, prefix, base_ip = calculate_num_networks_classless(hosts, ip_category)
    if prefix is None or num_networks == 0:
        return "Error: Cannot allocate subnet for the given number of hosts."
    block_size = 2 ** (32 - prefix)
    start_ip_int = ip_to_int(base_ip)
    # Define the maximum IP for the selected range
    if ip_category == "private":
        if base_ip == "192.168.0.0":
            max_ip_int = ip_to_int("192.168.255.255")
        elif base_ip == "172.16.0.0":
            max_ip_int = ip_to_int("172.31.255.255")
        else:  # 10.0.0.0
            max_ip_int = ip_to_int("10.255.255.255")
    else:  # public
        if base_ip == "198.51.100.0":
            max_ip_int = ip_to_int("198.51.100.255")
        elif base_ip == "131.107.0.0":
            max_ip_int = ip_to_int("131.107.255.255")
        else:  # 1.0.0.0
            max_ip_int = ip_to_int("1.255.255.255")
    networks = []
    max_display = 5  # Limit to first 5 networks
    for i in range(min(num_networks, max_display)):
        current_ip_int = start_ip_int + i * block_size
        if current_ip_int > max_ip_int:
            break  # Stop if the IP exceeds the valid range
        current_ip = int_to_ip(current_ip_int)
        networks.append(f"{current_ip}/{prefix}")
    results = ""
    for net in networks:
        ip, cidr = net.split('/')
        details = analyze_classless(ip, "decimal", int(cidr))
        results += f"Network {net}:\n{details}\n\n"
    if num_networks > max_display:
        results += f"... and {num_networks - max_display} more networks can be created.\n"
    return results

def generate():
    devices_str = devices_entry.get().strip()
    if not devices_str.isdigit():
        messagebox.showerror("Error", "Please enter a valid positive integer for devices.")
        return
    hosts = int(devices_str)
    if hosts < 1:
        messagebox.showerror("Error", "Devices must be at least 1.")
        return
    if hosts > 16777214:
        messagebox.showerror("Error", "Too many devices requested (max 16,777,214).")
        return
    gen_choice = gen_type.get()
    ip_cat = ip_category.get()
    results_text.delete(1.0, END)
    results_text.insert(END, "Generating...\n")
    root.update()
    time.sleep(0.5)
    if gen_choice == "classful":
        results = generate_classful(hosts, ip_cat)
    elif gen_choice == "classless":
        results = generate_classless(hosts, ip_cat)
    else:
        messagebox.showerror("Error", "Please select a generation type.")
        return
    results_text.delete(1.0, END)
    for i in range(0, len(results), 50):
        results_text.insert(END, results[i:i+50])
        results_frame.configure(bg="#e0ffff")
        root.update()
        time.sleep(0.05)
    results_text.insert(END, results[i+50:])

def analyze():
    ip_str = ip_entry.get().strip()
    if not ip_str:
        messagebox.showerror("Error", "Please enter an IP address.")
        return
    is_valid, mode, error_msg = validate_ip(ip_str)
    if not is_valid:
        messagebox.showerror("Invalid IP", error_msg)
        return
    results_text.delete(1.0, END)
    results_text.insert(END, "Analyzing...\n")
    root.update()
    time.sleep(0.5)
    if analysis_type.get() == "classfull":
        results = analyze_classfull(ip_str, mode)
    elif analysis_type.get() == "classless":
        cidr_str = cidr_entry.get().strip()
        if not cidr_str.isdigit() or not (1 <= int(cidr_str) <= 31):
            messagebox.showerror("Error", "CIDR prefix must be an integer between 1 and 31.")
            return
        netbit = int(cidr_str)
        results = analyze_classless(ip_str, mode, netbit)
    else:
        messagebox.showerror("Error", "Please select an analysis type.")
        return
    results_text.delete(1.0, END)
    for i in range(0, len(results), 50):
        results_text.insert(END, results[i:i+50])
        results_frame.configure(bg="#e0ffff")
        root.update()
        time.sleep(0.05)
    results_text.insert(END, results[i+50:])

def clear():
    ip_entry.delete(0, END)
    cidr_entry.delete(0, END)
    analysis_type.set("classfull")
    toggle_cidr()
    results_text.delete(1.0, END)
    results_frame.configure(bg="white")
    devices_entry.delete(0, END)
    gen_type.set("classful")
    ip_category.set("private")

def switch_functionality(event):
    selected = functionality.get()
    if selected == "Analyze IP":
        generator_frame.grid_remove()
        analyzer_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        toggle_cidr()
    elif selected == "Generate IP":
        analyzer_frame.grid_remove()
        generator_frame.grid(row=3, column=0, columnspan=2, sticky="ew")

def on_enter(btn, color):
    btn.configure(style="Hover.TButton")
    style.configure("Hover.TButton", background=color)

def on_leave(btn):
    btn.configure(style="TButton")

# GUI Setup
root = Tk()
root.title("IP Address Analyzer")
root.configure(bg="#33FFFF")

main_frame = Frame(root, bg="white", bd=5, relief=RIDGE)
main_frame.pack(padx=20, pady=20, fill=BOTH, expand=YES)

title_label = Label(main_frame, text="IP Address Analyzer", font=("Arial", 28, "bold"), bg="#00CED1", fg="white")
title_label.grid(row=0, column=0, columnspan=2, pady=20, sticky="ew")

subtitle_label = Label(main_frame, text="Analyze or generate IPs with ease and precision!", font=("Arial", 14, "italic"), bg="white", fg="#333")
subtitle_label.grid(row=1, column=0, columnspan=2, pady=5, sticky="ew")

functionality = StringVar(value="Analyze IP")
functionality_label = Label(main_frame, text="Select Functionality :- ", font=("Arial", 16), bg="white")
functionality_label.grid(row=2, column=0, sticky=E, padx=10, pady=10)
combobox = ttk.Combobox(main_frame, textvariable=functionality, values=["Analyze IP", "Generate IP"], state="readonly", font=("Arial", 16))
combobox.grid(row=2, column=1, sticky=W, padx=10, pady=10)
combobox.bind("<<ComboboxSelected>>", switch_functionality)

# Analyzer Frame
analyzer_frame = Frame(main_frame, bg="white")
analyzer_frame.grid(row=3, column=0, columnspan=2, sticky="ew")

ip_label = Label(analyzer_frame, text="Enter IP Address :- ", font=("Arial", 16), bg="white")
ip_label.grid(row=0, column=0, sticky=E, padx=10, pady=10)
ip_entry = ttk.Entry(analyzer_frame, font=("Arial", 16), width=30)
ip_entry.grid(row=0, column=1, sticky=W, padx=10, pady=10)

analysis_type = StringVar(value="classfull")
style = ttk.Style()
style.configure("TRadiobutton", font=("Arial", 14), background="white")
style.configure("TButton", font=("Arial", 14))
style.configure("Hover.TButton", font=("Arial", 14))
classfull_radio = ttk.Radiobutton(analyzer_frame, text="Classfull", variable=analysis_type, value="classfull", command=toggle_cidr)
classfull_radio.grid(row=1, column=0, sticky=W, padx=10, pady=10)
classless_radio = ttk.Radiobutton(analyzer_frame, text="Classless", variable=analysis_type, value="classless", command=toggle_cidr)
classless_radio.grid(row=1, column=1, sticky=W, padx=10, pady=10)

cidr_frame = Frame(analyzer_frame, bg="white")
cidr_label = Label(cidr_frame, text="CIDR :- ", font=("Arial", 16), bg="white")
cidr_label.pack(side=LEFT)
cidr_entry = ttk.Entry(cidr_frame, font=("Arial", 16), width=5)
cidr_entry.pack(side=LEFT, padx=5)
cidr_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")
cidr_frame.grid_remove()

button_frame = Frame(analyzer_frame, bg="white")
button_frame.grid(row=3, column=0, columnspan=2, pady=10, sticky="ew")
analyze_button = ttk.Button(button_frame, text="Analyze", command=analyze)
analyze_button.pack(side=LEFT, padx=10)
clear_button = ttk.Button(button_frame, text="Clear", command=clear)
clear_button.pack(side=LEFT, padx=10)

# Generator Frame
generator_frame = Frame(main_frame, bg="white")
generator_frame.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=10)

Label(generator_frame, text="Generate IP Addresses", font=("Arial", 16), bg="white").pack(pady=10)

# Devices Row
devices_row = Frame(generator_frame, bg="white")
devices_row.pack(fill=X, padx=10, pady=5)
devices_label = Label(devices_row, text="Number of devices per network :- ", font=("Arial", 14), bg="white")
devices_label.pack(side=LEFT)
devices_entry = ttk.Entry(devices_row, font=("Arial", 14), width=10)
devices_entry.pack(side=LEFT, padx=10)

# IP Category Row
ip_category_row = Frame(generator_frame, bg="white")
ip_category_row.pack(fill=X, padx=10, pady=5)
ip_category = StringVar(value="private")
private_ip_radio = ttk.Radiobutton(ip_category_row, text="Private IP", variable=ip_category, value="private")
private_ip_radio.pack(side=LEFT, padx=10)
public_ip_radio = ttk.Radiobutton(ip_category_row, text="Public IP", variable=ip_category, value="public")
public_ip_radio.pack(side=LEFT, padx=10)

# Generation Type Row
radio_row = Frame(generator_frame, bg="white")
radio_row.pack(fill=X, padx=10, pady=5)
gen_type = StringVar(value="classful")
classfull_gen_radio = ttk.Radiobutton(radio_row, text="Classful", variable=gen_type, value="classful")
classfull_gen_radio.pack(side=LEFT, padx=10)
classless_gen_radio = ttk.Radiobutton(radio_row, text="Classless", variable=gen_type, value="classless")
classless_gen_radio.pack(side=LEFT, padx=10)

# Generate Button
generate_button = ttk.Button(generator_frame, text="Generate", command=generate)
generate_button.pack(pady=10)

# Results Frame
results_frame = Frame(main_frame, bg="white", bd=3, relief=SUNKEN)
results_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
results_text = Text(results_frame, font=("Courier", 14), wrap=WORD, height=10)
scrollbar = Scrollbar(results_frame, command=results_text.yview)
results_text.config(yscrollcommand=scrollbar.set)
results_text.pack(side=LEFT, fill=BOTH, expand=YES)
scrollbar.pack(side=RIGHT, fill=Y)

# Exit Button
exit_frame = Frame(main_frame, bg="white")
exit_frame.grid(row=5, column=0, columnspan=2, pady=10, sticky="ew")
exit_button = ttk.Button(exit_frame, text="Exit", command=root.quit)
exit_button.pack()

# Configure Grid Weights
main_frame.grid_rowconfigure(4, weight=1)
main_frame.grid_columnconfigure(1, weight=1)

# Button Hover Effects
analyze_button.bind("<Enter>", lambda e: on_enter(analyze_button, "#228b22"))
analyze_button.bind("<Leave>", lambda e: on_leave(analyze_button))
clear_button.bind("<Enter>", lambda e: on_enter(clear_button, "#ff4500"))
clear_button.bind("<Leave>", lambda e: on_leave(clear_button))
generate_button.bind("<Enter>", lambda e: on_enter(generate_button, "#1e90ff"))
generate_button.bind("<Leave>", lambda e: on_leave(generate_button))
exit_button.bind("<Enter>", lambda e: on_enter(exit_button, "#dc143c"))
exit_button.bind("<Leave>", lambda e: on_leave(exit_button))

# Initialize Default State
toggle_cidr()
switch_functionality(None)

root.mainloop()