import subprocess
import random
import re
import os
import time
from datetime import datetime

LOG_DIR = "bigmac_logs"
PROGRAM_NAME = "bigmac"

WELL_KNOWN_MACS = [
    ("00:1A:2B:3C:4D:5E", "Intel"),
    ("00:0C:29:12:34:56", "VMware"),
    ("00:50:56:AB:CD:EF", "VMware"),
    ("00:14:22:01:23:45", "Dell"),
    ("3C:5A:B4:1A:2B:3C", "HP"),
    ("00:26:B9:1F:2D:3E", "Apple"),
    ("B8:27:EB:44:55:66", "Raspberry Pi"),
    ("D8:BB:2C:12:34:56", "Samsung"),
    ("00:1D:D8:99:88:77", "ASUSTek"),
    ("F0:27:65:4A:5B:6C", "Realtek"),
]

def generate_random_mac():
    mac = [0x00, 0x16, 0x3e,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(f"{x:02x}" for x in mac)

def is_valid_mac(mac):
    return re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac) is not None

def get_interfaces():
    output = subprocess.check_output("ip link show", shell=True, encoding='utf-8')
    interfaces = re.findall(r"\d+: ([^\s:]+):.*", output)
    return [i for i in interfaces if not i.startswith("lo")]

def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface], encoding='utf-8')
        match = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", output)
        return match.group(0) if match else None
    except Exception:
        return None

def change_mac(interface, new_mac):
    try:
        subprocess.call(["sudo", "ifconfig", interface, "down"])
        subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
        subprocess.call(["sudo", "ifconfig", interface, "up"])
        subprocess.call(["sudo", "dhclient", interface])
        return True
    except Exception:
        return False

def get_ip_address(interface):
    try:
        output = subprocess.check_output(["ip", "addr", "show", interface], encoding='utf-8')
        match = re.search(r"inet ([0-9.]+)", output)
        return match.group(1) if match else "Unavailable"
    except Exception:
        return "Unavailable"

def resolve_mac_vendor(mac):
    prefix = mac.upper()[0:8].replace(":", "")
    known_prefixes = {
        "000C29": "VMware",
        "001C42": "Parallels",
        "000D93": "Microsoft",
        "3C5AB4": "HP",
        "0026B9": "Apple",
        "B827EB": "Raspberry Pi",
        "D8BB2C": "Samsung",
        "F02765": "Realtek",
        "001AAD": "Intel",
        "F0D5BF": "Dell"
    }
    return known_prefixes.get(prefix, "Unknown Vendor")

def log_mac_change(interface, method, new_mac, result, old_mac, old_ip, new_ip):
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    timestamp = datetime.now().strftime("%m%d%y%H%M%S%f")
    full_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = f"{LOG_DIR}/{PROGRAM_NAME}_{timestamp}.log"

    vendor = resolve_mac_vendor(new_mac)

    with open(log_file, 'w') as f:
        f.write(f"========== {PROGRAM_NAME.upper()} LOG ==========" + "\n")
        f.write(f"Timestamp       : {full_time}\n")
        f.write(f"Hostname        : {os.uname().nodename}\n")
        f.write(f"Interface       : {interface}\n")
        f.write(f"Method Used     : {method}\n")
        f.write(f"Vendor          : {vendor}\n")
        f.write(f"Result          : {'Success' if result else 'Failure'}\n")
        f.write("\n--- MAC Address Change ---\n")
        f.write(f"Previous MAC    : {old_mac or 'Unknown'}\n")
        f.write(f"New MAC         : {new_mac}\n")
        f.write("\n--- IP Address Change ---\n")
        f.write(f"Previous IP     : {old_ip}\n")
        f.write(f"New IP          : {new_ip}\n")
        f.write("=" * 42 + "\n")

def select_interface():
    interfaces = get_interfaces()
    if not interfaces:
        print("[!] No valid interfaces found.")
        exit(1)
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")
    while True:
        try:
            choice = int(input("Select an interface to spoof: ")) - 1
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
        except ValueError:
            pass
        print("[!] Invalid selection. Try again.")

def select_mac_method():
    print("\nSelect MAC address method:")
    print("1. Randomized MAC")
    print("2. Choose from known vendor MACs")
    print("3. Enter custom MAC")
    print("4. Mirror MAC from network scan")
    choice = input("Choice [1/2/3/4]: ").strip()

    if choice == '1':
        return generate_random_mac(), "Random"
    elif choice == '2':
        for i, (mac, vendor) in enumerate(WELL_KNOWN_MACS):
            print(f"{i+1}. {mac:<20} - {vendor}")
        idx = int(input("Select from above [1-10]: ")) - 1
        if 0 <= idx < len(WELL_KNOWN_MACS):
            selected_mac, vendor = WELL_KNOWN_MACS[idx]
            return selected_mac, f"Vendor Select ({vendor})"
        else:
            print("Invalid. Defaulting to random.")
            return generate_random_mac(), "Random"
    elif choice == '3':
        mac = input("Enter your custom MAC (format XX:XX:XX:XX:XX:XX): ").strip()
        if is_valid_mac(mac):
            return mac, "Manual Entry"
        else:
            print("Invalid format. Defaulting to random.")
            return generate_random_mac(), "Random"
    elif choice == '4':
        scanned = []
        try:
            output = subprocess.check_output("arp -a", shell=True, encoding='utf-8')
            lines = output.strip().split("\n")
            for line in lines:
                match = re.search(r"\(?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?\s+.*(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").lower()
                    vendor = resolve_mac_vendor(mac)
                    scanned.append((ip, mac, vendor))
        except:
            pass

        if not scanned:
            print("[!] No devices found on the local network.")
            return generate_random_mac(), "Random (Fallback)"

        print("\n[🔍] Detected Devices:")
        print("-" * 60)
        print(f"{'No.':<5}{'IP':<20}{'MAC':<20}{'Vendor'}")
        print("-" * 60)
        for i, (ip, mac, vendor) in enumerate(scanned):
            print(f"{i+1:<5}{ip:<20}{mac:<20}{vendor}")
        print("-" * 60)

        try:
            idx = int(input("Select device to mirror [1–20]: ")) - 1
            if 0 <= idx < len(scanned):
                chosen_mac = scanned[idx][1]
                return chosen_mac, f"Mirror ({scanned[idx][2]})"
        except:
            pass

        print("[!] Invalid selection. Defaulting to Random.")
        return generate_random_mac(), "Random"
    else:
        print("Invalid choice. Defaulting to Random.")
        return generate_random_mac(), "Random"

if __name__ == "__main__":

    BANNER = r'''
    [ 

............#%@@@@@%@%%%%%%%%%%##**++==--:::::::..........::-=*#%%%%#%%###%#%##%##%#%%%%%:..........
............%%@@@@@@%%%@%%%%%%##**++==----:::::............::-=+#%%%%#%%%%###%#%%%%%#%%%%%..........
...........%%@@@@%@%%%%%%%%%%##**++===---:::::..............::-=**#%%%%%##%##%#%#%#%%%%%%%*.........
..........%%%@@@@@@%%%%%%%%%##**+++==----::::.:...............:-=+#%%%%#%#%%%###%%%%%%%%%%%+........
.........-%%@@@@@@%@%%%%%%%%##*+++==----:::::::...............::-+*#%%%%%#%%%%##%%%%%%%%%%%=:.......
.........*%%@@@@@%@%%%%%%%%%##**++===----::::::::.........::-**%#%%%%%%%%%%%%%%%%%%%%%%%%%%%:.......
........#%%%@@@@@%%%%%%%%%%%%%%%%%%%%%###+=-::::::.:::==%*+#**%#%%%%%%@@%%%%##%%##%%%%%%%%@%==......
.......:*%%@@@@@@%%%%%%%%%%%%%%%%%%%%%%%##*=--::::::-=****#**+-::::=+*#%%%%#%%%###%%%%%%%%%%#-:.....
.......+%#%@@@@@@%%%%%%%%%%##*++==--==+***++=--::::::-==------::..:-=*#%%%%%#%%%#%%%%%%%%%%%%=.:....
......+-%%%@@@@@%@%%%%%%%%%##*++=--:::--==++==--::::::---------=+**++*#%%%%%%%#%%#%%%%%%%%@%%#=:....
......#+%#%@@@@@@%%%%%%%%%%%%%%%%%##-=::--=++==-::..:::--===#%%%%%%%%#%%%%%%%%%%%%#%%%%%%%@@%%:::...
.....:%%#%%@@@@@%@%%%%%%%%%%%%%%#%%%++%*:--=++=-:.....:-==###%%%%%:=%%%%%%%%%#%%%%%%%%%@%%@%%%#::...
.....####%@@@%@@@%%%%%%%%%%%%%%#+%%%%%-#@:-====-:.....::-##*+*%%%-+++***##%%%%%%%%%%%%%@@%@@%%%.-:..
....:#*#%%%@@@@%%%%%%%%%%%####**+===-:::=::-===-:......:::-===--------=++*#%%%#%%%%%%%%%%@@%%%%*.:..
....%=#%%%@@@@@%%%%%%%%%%#*****+++==--:::::-===-:..........::::::::..::-=+*#%%%%%%%%%%%@@@@@%%%%*+:.
...:=#%%#@@@@@@%%%%%%%%%%*+==----::::::::::-===-:......................:-=+*%%%%%%%%%%%@@@@@%%%%*=..
...:#*%#%%%@@@@%%%@%%%%%#*=--:::::.....::::-=++-:.......................:-=*#%%%%%%%%%%%%@%%%%%#%#+.
..:=%%##%%@@@@@@@%%%%%%%%*=--:::........::-=+*+-:........................:=+##%%%%%%%%%%%%@%%%%##=+:
..#+%%:#%%@@@%@@@%%%%%%%%#+=-::........::-=+**+-:........................:-=*#%%%%%%%%%@%%@@%%%%%#*:
..-##%++%%@@@@@%@%%%%%%%%#*+--::......:::-+##*=-:........................:-=*#%%%@@%%%@@%%%@%%%%+-##
..##+%-*%%@@@@@@@@%%%%%%%%#*+--:::...:::-+###*=-:.........:::::.........::-=*##%@@@%@%%@@@%%@%%%*#++
..+%-%*%%%@@@%@@@%%%%%%%%%##*=--:::::::-=#####*=-:.......:::-:::::....:::--=*#%@%@@@@@%%%%%%%%%%*+-*
.=-#.=#%%%%@@%@@%@%%%%%%%%%%#*+=--::::-=*%#####*+=--=%*-::.:---:::::::::--=+*#%@%%@@@%@%%@%%%%%%#:=-
.=-#.:#%%%%@@@@@%@%%%%%%%%%%%#*+==----=+*#%%%%%%#*++===-....:------::----==+*#%@@%%%@@@@%@%%%%%*#**-
:*:%+:%%%%@@@@@%@@%%%%%%%@%%%%#*++===+**********+==-:........:-===------==++#%@@@%%%%%@@@%@%%%%%##=:
:+:=#%%%%%@@%@@%%%%%%%%%%@@%%%%##****###****++=-:--:.........:-=====--===++*%@@%%%%%%%@%%@%%%%%%#+-+
:*+=##%%%%@@@@@%%%%@%%%%%%@%%%%%##*##%%%%#######****++==-::::-=++==---===+*#@@@%%%%%%%@@%%%%%%%%#++:
:=:-*%%%%%%@@@%@%%%%%%%%%%%@%%%%%####%%%%%%%###+++*-:-==###%%%*+==----==+*#%@@@@%%%%%%%@@%%%%%%%##+=
:=-.%%%%%%%@@%@%%%%%%%%%%%%%@%%%%%###%%@*.*.::*++..=.=-++++==%%+=----==+*#%@@%%%%%%%%%%%%%%%%%%%%###
.=:-#%%%%%@@@@@@%@%%%%%%%%+-:::-::...::------.++==-==+======-.===---==+*#%@%%@@%%%%%%%%%%%%%%%%%%#+#
.=:#%%%=%%@@@@@@%@%%*::::-:...............:.-:+:=+-=.==+:+%*:...::.....:%%@%%%%%%%%%%%%%%%%%%%%%%##=
.-.-#%##%%%%@@@@@@%*-:.........:::...:::::::+.=-==+===.---.+#=---::..........%%%%%%%%%%%%%%%%%%%%#=+
.-:*%%##%%@@@%@%%%%-:...:-::...............+===:==.====-.:....:-::::.....:.......-%%%%%%%%%%%%%%%%#%
.-:#%#*#%%%%@%@@*+-:::*:......:::::::..:+===.=====---==+%+:::::.................::.%%@%%%%%%%%%%%%=#
.=:=%%#+%%%@@%@#=:::-=-:::::...........-===.====----.-.--.#:::-----:-::..............%%%%%%%%%%%%%%:
:=+###+%%%%%@@#=-:-=--#-.......:-+++*====.==---------::::-**::..::.......:==--:.......%%%%%%%%%%%%#*
::*%=#%%%%%%%+---*=--*-:...::+%##*+=====.:=----::.::::::::::#=-:.................:......%%%%%%%%%%*#
:.%*:*#%%%%+=---+--=+:....:@%##**+=====------::::::............-**+==-::.................%%%%%%%%%#%
.+%+#%=%%---:-+---+=:....:@@%%**++====---::.::...................:-+#%#%*+=--::...........:%%%%%%%%#
.-:=###=::::--::-*=:....*@%%%%%%%%*+==---:::::..................####*###%@@@@#*+-:..........:%%%%%#*
+%++#%#=-=--:::-+-:....%@%%%%%%%#%*####*#%%%#++*===:-+=%%:::*+----=-:::::-@@%@@%+-:............%%%%+
+.+*+%%##+----=-::....:@#%#+#%%%%%%*#%%%%=-=%*=#*#-..:=%#=::--:::::::............-+-:...........%%%#
#.#+#%%%#*+++-::......@@*%#+-+%%%%%%..::--++.:-=--.--*+**++=--#++++====-::..........*-...........%%%
..*%%@@%%###+-::.....-@@@%##=:-%%%#%%:*******+##***+=--:.:::...-%%##%*+=#@**+=-:................%%#%
%%%%@@@%%#%%+-::....:=+#@%%##+:.-%%%%%%%###*====++-::.........#+++**--=*%@@@@@%*=:..............%%%%
@%%@@@@%%%%#+-::...::--=*#%%###+-::+%%###+=****#####%@*::....=+*#-...-*#*#@@%#%%%#+:...........:%%%%
@@%@@@@@%%%#=-:....:::--=+#%#####*=:..:#%%%%#**#*===-+=+++=.%#:....:=+*%-+#####%%%%%#=:........=%%%%
@@@@@@@@%%%*=::....:::::-=+#%%######*+=:....-+*%%%%%%%#*+-:.....:-==+##-=-***##%%%%%#*-:......:*%%%%
@%@@@@@@%%#+-::....::::::--+*#%%+*#####**+=--::............::--===+%#...*+++**##%%%%%#+-:.....:##%%%
%@@@@@@%%%#+-::....:....:::-=+#%%%#**#####*##***++==========+++%.......*+++++**#%%%%%%*=:.....:*%%%%
@%@@@@@@%#*=-:.....:.......:-=+*##%%%%#++++###***********#*###:......##**+=++++*##%%%%*+-:....:+%%%%
%@@@@@@@%#+=::.....:.......::-=*#%%%%%%%%%%+..=#=+#*.::.::+........%@@%#*++===++*#%%%#*=-:.....-%%%#
%@@@@@@@%#+=::.............::-+@%%%%%%%%%%%%..::==--..:**####%%%%%@@@@@%#*++===+**#%%#*=::.....:%%%%
@@@@@@@@%#+-::.....:......::-+@%%%%%%%%######+..-=-+*******##%%%%@%@@@@@%#*++===+*#%%#+-:......:%%%%
@@@@@@@%%*=-:......:....::--+@@%%%%%#%######****#******+***##%%%%%@@@@@@@%#*++==+*#%%*+-:......:%%%%

 ]
    '''

    print(BANNER)
    print("""

         🍔🕶️  BIGMAC - MAC Spoof & Intel Toolkit 🕶️🍔
         =======================================
    """)

    interface = select_interface()
    mac, method = select_mac_method()
    old_mac = get_current_mac(interface)
    old_ip = get_ip_address(interface)

    print(f"\n[+] Interface: {interface}")
    print(f"[+] Current MAC: {old_mac}")
    print(f"[+] Attempting to change MAC to {mac} via {method}")

    success = change_mac(interface, mac)
    time.sleep(2)  # wait for DHCP to assign IP
    new_ip = get_ip_address(interface)
    log_mac_change(interface, method, mac, success, old_mac, old_ip, new_ip)

    if success:
        print(f"[✔] MAC successfully changed to {mac}")
    else:
        print(f"[✘] MAC change failed")
