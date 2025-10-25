import pydivert
import threading
import subprocess
import time
import psutil
import ctypes
import json
import sys
import os

# Read the configuration from the JSON file
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Read the payloads from the JSON file
with open("payloads.json", "r") as payloads_file:
    payloads = json.load(payloads_file)
    
# Read the payloads for Login port from the JSON file
with open("payloads_login.json", "r") as payloads_file:
    payloads_login = json.load(payloads_file)
    
# Read the payloads to check flood from the JSON file
with open("payloads_flood.json", "r") as payloads_flood_file:
    payloads_flood = json.load(payloads_flood_file)


# Extract the configuration values
# DON'T EDIT FROM HERE USE config.json FILE!!

BAN_DURATION = config.get("BAN_DURATION", 0)
MAX_TEMP_BANS = config.get("MAX_TEMP_BANS", 0)
TIME_FOR_MAX_PACKETS = config.get("TIME_FOR_MAX_PACKETS", 0)
MAX_PACKETS_THRESHOLD = config.get("MAX_PACKETS_THRESHOLD", 0)
BLOCKED_PACKET_THRESHOLD = config.get("BLOCKED_PACKET_THRESHOLD", 0)
BLOCKED_PORT = config.get("BLOCKED_PORT", 0)
LOGIN_PORT = config.get("LOGIN_PORT", 0)
FIREWALL_RESTART = config.get("FIREWALL_RESTART", "False")
FIREWALL_RESTART_HOURS = config.get("FIREWALL_RESTART_HOURS", 0)
PROCESS_MONITOR = config.get("PROCESS_MONITOR", "True")
PROCESS_NAME = config.get("PROCESS_NAME", "D2GS.exe")
PROCESS_PATH = config.get("PROCESS_PATH", r"C:\D2GS\D2GS.exe")
BANNED_IPS_FILE = config.get("BANNED_IPS_FILE", "banned_ips.json")
PERMABAN_IPS_FILE = config.get("PERMABAN_IPS_FILE", "permaban_ips.json")
TEMP_PERMABAN_IPS_FILE = config.get("TEMP_PERMABAN_IPS_FILE", "temp_permaban_ips.json")

# Set the window title
ctypes.windll.kernel32.SetConsoleTitleW("PvPGN Firewall")

# Clear terminal variable
cls = lambda: os.system('cls' if os.name=='nt' else 'clear')

# Initialize banned IPs dictionary
banned_ips = {}

# Initialize permabanned IPs dictionary
permaban_ips = {}

# Initialize tempbanned IPs dictionary
temp_permaban_ips = {}

# Initialize packet count dictionary
packet_count = {}

# Read Banned IP File  
def load_banned_ips():
    try:
        with open(BANNED_IPS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_banned_ips(banned_ips):
    with open(BANNED_IPS_FILE, "w") as f:
        json.dump(banned_ips, f)

# Read Permaban IP File        
def load_permaban_ips():
    try:
        with open(PERMABAN_IPS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_permaban_ips(permaban_ips):
    with open(PERMABAN_IPS_FILE, "w") as f:
        json.dump(permaban_ips, f)

# Read temporal banned IP File
def load_temp_permaban_ips():
    try:
        with open(TEMP_PERMABAN_IPS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_temp_permaban_ips(temp_permaban_ips):
    with open(TEMP_PERMABAN_IPS_FILE, "w") as f:
        json.dump(temp_permaban_ips, f)

#Block malicius packets in BLOCKED_PORT 4000 (D2GS)
def block_packet(packet, w):

    # Check the packets in the "banned_ips.json" file
    # Here packets are BAD, so any of them are allowed to pass to D2GS process.
    # Here we don't apply a temporary ban, only a packet count, if the IP send more than
    # the ammount of packets set in MAX_PACKETS_THRESHOLD, this IP go to a permanent ban.
    
    payload = bytes(packet.tcp.payload)
    if packet.tcp.dst_port == BLOCKED_PORT and (payload.startswith(tuple(bytes.fromhex(p) for p in payloads["starting_with"])) or payload in (bytes.fromhex(f) for f in payloads["fixed"])):
        source_ip = packet.src_addr

        #Read the Permaban file, for future check
        with open(PERMABAN_IPS_FILE, "r") as json_file:
           load_permaban = json.load(json_file)
 
        # Check if the Source IP is permanent banned in files
        if source_ip in load_permaban:
         check_ban = load_permaban[source_ip]
         if check_ban >= 1:
           return
         else:
           pass
              
        # This will start or add a number in the packet count for this IP
        current_time = time.time()
        if source_ip in packet_count:
            packet_count[source_ip] += 1
        else:
            packet_count[source_ip] = 1
            
        # Display blocked packet and source IP
        print(time.strftime("%H:%M:%S"),f"- Malicious packet has been detected: {payload} - From Source IP: {source_ip} - Send {packet_count[source_ip]} packets", flush=True, file=open('log.txt', 'a'))

        # Permanent ban the source IP if it exceeds a certain threshold of blocked packets
        if packet_count[source_ip] > BLOCKED_PACKET_THRESHOLD:
            print(time.strftime("%H:%M:%S"),f"- The IP: {source_ip} was permanent banned, because reach the malicious packet threshold.", flush=True, file=open('log.txt', 'a'))
            permaban_ips[source_ip] = 1
            save_permaban_ips(permaban_ips)
            del packet_count[source_ip]
            return

        # We never send the packet to effectively block it.

    else:
        # Allow the packet to pass through
        w.send(packet)

#Block malicius packets in LOGIN_PORT (Login PvPGN)
def block_login_packet(packet, w):

    # Check the packets in the "payloads_login.json"
    # Here packets are BAD, so any of them are allowed to pass to the login port.
    # Here we only apply temporary ban, just to avoid try to login with RedVex or similar cheats.
    
    payload_login= bytes(packet.tcp.payload)
    if packet.tcp.dst_port == LOGIN_PORT and (payload_login.startswith(tuple(bytes.fromhex(p) for p in payloads_login["starting_with"])) or payload_login in (bytes.fromhex(f) for f in payloads_login["fixed"])):
        source_ip = packet.src_addr
                
        # Because send a Malicius packet to the Login get a Temporary ban.
        current_time = time.time()
        print(time.strftime("%H:%M:%S"),f"- The IP: {source_ip} was temporarily banned because sent malicious packets to login.", flush=True, file=open('log.txt', 'a'))
        banned_ips[source_ip] = current_time
        save_banned_ips(banned_ips)
        
        # We never send the packet to effectively block it.

    else:
        # Allow the packet to pass through
        w.send(packet)

#Block flood packets in BLOCKED_PORT (D2GS)
def block_flood_packet(packet, w):
    
    # Check the packets in the payloads_flood.json
    # Because this packets are not bad in low ammount this packets are allow it to pass, but
    # apply a temporary ban if certain amount are send it in a specific time.
    # And after a deffined ammount of temporary bans MAX_TEMP_BANS , the IP go to a permanent ban.
    
    payload_flood = bytes(packet.tcp.payload)
    if packet.tcp.dst_port == BLOCKED_PORT and (payload_flood.startswith(tuple(bytes.fromhex(p) for p in payloads_flood["starting_with"])) or payload_flood in (bytes.fromhex(f) for f in payloads_flood["fixed"])):
        source_ip = packet.src_addr
        
        #Read the Permaban file, to update de dictionary for future check
        with open(PERMABAN_IPS_FILE, "r") as json_file:
           permaban_ips = json.load(json_file)
           
        #Read the Temp file, to update de dictionary for future check
        with open(TEMP_PERMABAN_IPS_FILE, "r") as json_file:
           temp_permaban_ips = json.load(json_file)
        
        #Read the Banned IPs File, to update de dictionary for future check
        with open(BANNED_IPS_FILE, "r") as json_file:
           banned_ips = json.load(json_file)
 
        # Check if the source IP is permanent banned in files
        if source_ip in permaban_ips:
         check_ban = permaban_ips[source_ip]
         if check_ban >= 1:
           return
         else:
           pass

        # If not permaban, let's check if the source IP is temp banned and how many times
        if source_ip in temp_permaban_ips:
            ban_temp_count = temp_permaban_ips[source_ip]
            # The IP has been banned MAX_TEMP_BANS times, so write in the permanent file
            if ban_temp_count >= MAX_TEMP_BANS:
                print(time.strftime("%H:%M:%S"),f"- The IP: {source_ip} was banned too many times, go to permanent ban.", flush=True, file=open('log.txt', 'a'))
                permaban_ips[source_ip] = 1
                save_permaban_ips(permaban_ips)
                # And clear the temporal ban file, because now this IP it's permanent
                del temp_permaban_ips[source_ip]
                save_temp_permaban_ips(temp_permaban_ips)
                return
            else:
                pass
                
        # Here we check if have some Temporary ban, and if time to release it from there.
        if source_ip in banned_ips:
            ban_start_time = banned_ips[source_ip]
            ban_elapsed_time = time.time() - ban_start_time
            if ban_elapsed_time < (BAN_DURATION * 60):
                # IP is still banned, don't send the packet
                return
            else:
                # Ban duration has elapsed, remove the IP from the banned list
                del banned_ips[source_ip]
                save_banned_ips(banned_ips)
                
        # Here Check if the source IP has exceeded the maximum packet rate
        current_time = time.time()
        if source_ip in packet_count:
            packet_count[source_ip].append(current_time)
            
            #Here set the time using the variable TIME_FOR_MAX_PACKETS to know the time space.
            #Then we set the MAX_PACKETS_THRESHOLD so between this you get the condition
            
            packet_count[source_ip] = [t for t in packet_count[source_ip] if current_time - t <= TIME_FOR_MAX_PACKETS]
            w.send(packet)
            if len(packet_count[source_ip]) > MAX_PACKETS_THRESHOLD:
            
            #Because the IP send the ammount of packets in the time get 1 point for de future permaban.
                if source_ip in temp_permaban_ips:
                    # IP got one point
                    temp_permaban_ips[source_ip] += 1
                    save_temp_permaban_ips(temp_permaban_ips)
                else:
                    # If the IP never exist in the file, let's put it
                    temp_permaban_ips[source_ip] = 1
                    save_temp_permaban_ips(temp_permaban_ips)
                    
                # IP has exceeded the maximum packet rate, ban the IP for moment
                print(time.strftime("%H:%M:%S"),f"- The IP: {source_ip} was temporarily banned because it sent too many packets.", flush=True, file=open('log.txt', 'a'))
                banned_ips[source_ip] = current_time
                save_banned_ips(banned_ips)
                del packet_count[source_ip]
                return
        else:
            packet_count[source_ip] = [current_time]

        # Display blocked packet and source IP
        print(time.strftime("%H:%M:%S"),f"- Flood packet has been detected: {payload_flood} - From Source IP: {source_ip}", flush=True, file=open('log.txt', 'a'))
        
    else:
        # Allow the packet to pass through
        w.send(packet)

#Check if the IP its temporary banned or permanent to avoid login (PvPGN)
def login_ban_check(packet, w):
    
    # Check if the IP have Permanent ban or any Temporal ban to avoid get login
    # and if have any temporal ban release it from there if is the time to do it.

    payload_flood = bytes(packet.tcp.payload)
    if packet.tcp.dst_port == LOGIN_PORT:
        source_ip = packet.src_addr
        
        #Read the Permaban file, to update de dictionary for future check
        with open(PERMABAN_IPS_FILE, "r") as json_file:
           permaban_ips = json.load(json_file)
           
        #Read the Banned IPs File, to update de dictionary for future check
        with open(BANNED_IPS_FILE, "r") as json_file:
           banned_ips = json.load(json_file)
 
        # Check if the source IP is permanent banned in files
        if source_ip in permaban_ips:
         check_ban = permaban_ips[source_ip]
         if check_ban >= 1:
             print(time.strftime("%H:%M:%S"),f"- The IP: {source_ip} - Try to login, but have permanent ban.", flush=True, file=open('log.txt', 'a'))
         return
        else:
           pass
        
        # Here we check if have some Temporary ban, and if time to release it from there.
        current_time = time.time()
        if source_ip in banned_ips:
            ban_start_time = banned_ips[source_ip]
            ban_elapsed_time = time.time() - ban_start_time
            if ban_elapsed_time < (BAN_DURATION * 60):
                # IP is still banned, don't send the packet
                return
            else:
                # Ban duration has elapsed, remove the IP from the banned list
                del banned_ips[source_ip]
                save_banned_ips(banned_ips)
        
        # Check if the source IP have a temporal time ban
        if source_ip in banned_ips:
         print(time.strftime("%H:%M:%S"),f"- The IP: {source_ip} - Try to login, but have temporary ban.", flush=True, file=open('log.txt', 'a'))
         return
        else:
           w.send(packet)
    else:
     # Allow the packet to pass through
     w.send(packet)

#Here starts the capture process for Malicious, Flood, and Login packets.
def packet_capture():
    print(f"Capturing packets in D2GS  = ENABLED")
    with pydivert.WinDivert(f"tcp.DstPort == {BLOCKED_PORT} and tcp.PayloadLength > 0") as win_divert:
        for packet in win_divert:
            block_packet(packet, win_divert)

def packet_login_capture():
    print(f"Capturing packets in PvPGN = ENABLED")
    with pydivert.WinDivert(f"tcp.DstPort == {LOGIN_PORT} and tcp.PayloadLength > 0") as win_divert:
        for packet in win_divert:
            block_login_packet(packet, win_divert)
            
def packet_flood_capture():
    with pydivert.WinDivert(f"tcp.DstPort == {BLOCKED_PORT} and tcp.PayloadLength > 0") as win_divert:
        for packet in win_divert:
            block_flood_packet(packet, win_divert)

def login_ban_capture():
    with pydivert.WinDivert(f"tcp.DstPort == {LOGIN_PORT} and tcp.PayloadLength > 0") as win_divert:
        for packet in win_divert:
            login_ban_check(packet, win_divert)           

#Process related to restart, and monitor

def restart_process(process_name, process_path):
    try:
        subprocess.Popen(
            process_path,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
        print(time.strftime("%Y-%m-%d"),f"- The process {PROCESS_NAME} has been restarted", flush=True, file=open('log.txt', 'a'))
    except subprocess.CalledProcessError:
        print(time.strftime("%Y-%m-%d"),f"- The process fail {PROCESS_NAME} to be restarted, check location in config.json", flush=True, file=open('log.txt', 'a'))

def firewall_restart():
 print(f"Automatic Firewall Restart = ENABLED")
 if FIREWALL_RESTART == "True":
    time.sleep(FIREWALL_RESTART_HOURS * 3600)
    print(time.strftime("%Y-%m-%d"),f"- The Firewall it's restarting", flush=True, file=open('log.txt', 'a'))
    time.sleep(5)
    cls()
    python = sys.executable
    os.execl(python, python, * sys.argv)
 else:
    pass

def process_monitor():
    print(f"Restart D2GS if crash      = ENABLED")
    while True:
        process_running = any(proc.name() == PROCESS_NAME for proc in psutil.process_iter())

        if not process_running:
            restart_process(PROCESS_NAME, PROCESS_PATH)

        time.sleep(5)

# Set the process priority to real-time
current_process = psutil.Process()
current_process.nice(psutil.REALTIME_PRIORITY_CLASS)

#Some welcome stuff
print(f"Welcome to the Firewall! v1.1")
print(f"=============================\n")
print(f"This project was made by GecKoTDF and MayhemARG")
print(f"Check any info in forums.pvpgn.pro.\n")

print(f"D2GS  Port = {BLOCKED_PORT}")
print(f"PvPGN Port = {LOGIN_PORT} \n")

print(f"", flush=True, file=open('log.txt', 'a'))
print(time.strftime("%Y-%m-%d"),f"- Today it's a new fresh restart in the PVPGN Firewall...\n", flush=True, file=open('log.txt', 'a'))

# Start the diferent threads to work
packet_capture_thread = threading.Thread(target=packet_capture)
packet_login_capture_thread = threading.Thread(target=packet_login_capture)
packet_flood_capture_thread = threading.Thread(target=packet_flood_capture)
login_ban_capture_thread = threading.Thread(target=login_ban_capture)
process_monitor_thread = threading.Thread(target=process_monitor)
firewall_restart_thread = threading.Thread(target=firewall_restart)

if PROCESS_MONITOR == "True":
    # Value True monitor process, capture, and restart firewall.
    packet_capture_thread.start()
    packet_login_capture_thread.start()
    packet_flood_capture_thread.start()
    login_ban_capture_thread.start()
    firewall_restart_thread.start()
    process_monitor_thread.start()
else:
    # Value False only capture and restart firewall
    packet_capture_thread.start()
    packet_login_capture_thread.start()
    packet_flood_capture_thread.start()
    login_ban_capture_thread.start()
    firewall_restart_thread.start()

print(f"")
print(f"Everything it's working fine, check the log.txt to see any capture.\n")
print(f"Good Luck! - By the way DieTesseract\n")
