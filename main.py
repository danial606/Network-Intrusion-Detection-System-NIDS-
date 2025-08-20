import os
import ctypes
from scapy.all import get_if_list, conf

from nids_core import NIDS
from webapp import create_app

def check_admin_privileges():
    try:
        is_admin = (os.name == 'nt' and ctypes.windll.shell32.IsUserAnAdmin()) or \
                   (os.name != 'nt' and os.geteuid() == 0)
    except Exception as e:
        print(f"Could not check for admin rights: {e}")
        is_admin = False
    
    if not is_admin:
        print("\033[91mError: This script requires root/administrator privileges.\033[0m")
        if os.name == 'nt':
            print("Please re-run this script as an Administrator.")
        else:
            print("Please run it with 'sudo python main.py'")
        exit(1)

def choose_interface():
    interfaces = get_if_list()
    print("Available Network Interfaces:")
    for i, iface in enumerate(interfaces):
        details = conf.ifaces.get(iface)
        print(f"  {i}: {iface} ({details.name if details else 'N/A'})")
    
    while True:
        try:
            choice = int(input("Please select the interface to monitor (by number): "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print("Invalid choice.")
        except (ValueError, IndexError):
            print("Invalid input.")

if __name__ == "__main__":
    check_admin_privileges()
    
    nids = NIDS()
    
    selected_interface = choose_interface()
    nids.interface = selected_interface
    
    app = create_app(nids)
    
    print("\n--- NIDS Web UI ---")
    print(f"Open your browser and go to http://127.0.0.1:5000")
    print("Use the web interface to start and stop network monitoring.")
    app.run(host='127.0.0.1', port=5000, debug=False)