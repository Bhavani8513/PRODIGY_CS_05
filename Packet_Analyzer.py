from scapy.all import * 
def main():
    print("||==||==||==+ PACKET ANALYZER + ==||==||==||")
    while True:
        choice = input("\n1. Simple Packet Sniffer \n2. Packet Sniffer with HexDump Data\n3. Packet sniff and Capture file Sotrage\n4. Quit\nEnter Your Choose : ")
        try:
            if choice == "1":
                print("Ctrl + C To end Packet Capturing")
                packets = sniff()
                print(packets.summary(),"\n" ,packets)
            elif choice == "2":
                print("Ctrl + C To end Packet Capturing")
                packets = sniff()
                print(packets, packets.hexdump())
            elif choice == "3":
                print("Ctrl + C To end Packet Capturing")
                packets = sniff()
                print("File with name \"Capture.pcap\" will be stored in current script Directory.")
                wrpcap("Capture.pcap", packets)
            elif choice == "4":
                print("\nExiting...")
                exit()
            else:
                print("Invalid choice ,Please Try again")
        except KeyboardInterrupt:
            print("Packet sniffing completed!!!\n\n")

if __name__ == "__main__":
    main()
