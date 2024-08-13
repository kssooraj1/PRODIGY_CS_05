The packet_sniffer function creates a raw socket to capture packets.
It sets up the socket to capture packets and binds it to the local machine.
The program enters an infinite loop, capturing packets and parsing them to extract relevant information.
It extracts the source and destination IP addresses, protocol, TTL, and payload data from each packet.
It prints the packet information to the console.
The program stops when the user presses 'Ctrl+C'.
Note: This program uses raw sockets, which require administrative privileges to run. Additionally, this program is for educational purposes only, and I do not condone or encourage the use of packet sniffers for malicious purposes.

Important: Packet sniffers can be used for malicious purposes, such as intercepting sensitive data or violating user privacy. It is essential to use this program responsibly and only with the explicit permission of the network administrator. Additionally, be aware of the legal and ethical implications of using packet sniffers in your jurisdiction.

Disclaimer: This program is for educational purposes only, and I do not condone or encourage the use of packet sniffers for malicious purposes.

 execute it using Python (e.g., python packet_sniffer.py) with administrative privileges. The program will start capturing and logging network packets. Press 'Ctrl+C' to stop the program.

Output: The program will log each packet with relevant information, including source and destination IP addresses, protocols, TTL, and payload data.
