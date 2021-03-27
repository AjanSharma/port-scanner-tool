import nmap
from pprint import pprint

while True:
	print("""\nSelect the option from below List.\n
				1 - Device Scan
				2 - Network Scan
				0 - Close Application""")
	inp = input("\nEnter your choice here: ")

	if inp == "1":

		scanner = nmap.PortScanner()

		# Target contains the ip address
		target = input("\nEnter the IP address of the target: ")

		# Scanning and storing result in 
		raw_data = scanner.scan(target, '1-1024', '-v -sS -sV -O -A -e eth0')

		#Extracting usefull data out of raw data
		print("\n ******************************  {}  ******************************".format(target))

		#Device Specific information
		#Displaying MAC address
        try:
            mac_addr = raw_data['scan'][target]['addresses']['mac']
            print("\n====>>>> MAC address: {}".format(mac_addr))
        except KeyError:
            pass

        #Displaying Operating system
        operating_system = raw_data['scan'][target]['osmatch'][0]['name']
        print("====>>>> Operating system: {}".format(operating_system))

        #Displaying Device uptime
        uptime = raw_data['scan'][target]['uptime']['lastboot']
        print("====>>>> Device uptime: {}".format(uptime))

        #Ports Information
        print("\n\n******PORTS******\n")

        for port in list(raw_data['scan'][target]['tcp'].items()):
            print("====>>>> {} | {} | {}".format(port[0], port[1]['name'], port[1]['state']))

        #More information
        print("\n\n****** More Information ******\n")

        #NMAP command
        print("====>>>> NMAP command: {}".format(raw_data['nmap']['command_line']))

        #NMAP version
        version = str(scanner.nmap_version()[0]) + "." + str(scanner.nmap_version()[1])
        print("====>>>> NMAP version: {}".format(version))

        #Time elapsed
        print("====>>>> Time elapsed: {}".format(raw_data['nmap']['scanstats']['elapsed'] + "seconds"))

    elif inp == "2":

    	scanner = nmap.PortScanner()

    	print("\n Scanning.....")

    	#Scanning the device
        raw_data = scanner.scan(ports = '1-1024', arguments = '-sS -e eth0 -iL /home/Desktop/ip.txt')

        for device in raw_data['scan']:
            print("\nPorts open on {}:".format(device))
            for port in raw_data['scan'][device]['tcp'].items():
                if port[1]['state'] == 'open':
                    print("====>>>>" + str(port[0]) + "|" + port[1]['name'])

        continue

    elif inp == "0":
        print('\nTerminating....\n')

		break

    else:
        print("\nInvalid input\n")

        continue