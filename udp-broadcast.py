import socket
import uuid
import fcntl
import json
import struct

# Constants
ETHERNET_INTERFACE = 'enp0s31f6'
UDP_PORT = 13401

# Function to get the MAC address of the network interface
def get_mac_address():
    # Use the uuid module to get the MAC address
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
    return mac

# Function to get the IP address of the machine
def get_ip_address(ifname=ETHERNET_INTERFACE):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ip_addr = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except IOError:
        ip_addr = '127.0.0.1'  # default to localhost if unable to get IP address
    return ip_addr

def calculate_crc(data):
    return 0xFFFF

def main():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Bind the socket to all interfaces on port UDP_PORT
    server_socket.bind(('', UDP_PORT))

    print("Listening for broadcast messages on port {}...".format(UDP_PORT))

    # Keep track of the last message to prevent duplicate responses
    last_message = None
    last_sender = None


    while True:
        # Receive data from the socket
        data, addr = server_socket.recvfrom(1024)

        # Check if the received message is a duplicate to avoid double processing
        if data == last_message and addr == last_sender:
            continue  # Skip processing this message as it's a duplicate

        print(f"Received message: {data} from {addr}")

        # Update last_message and last_sender to prevent duplicates
        last_message = data
        last_sender = addr

        # Get machine's IP and MAC address
        mac_address = get_mac_address()
        ip_address = get_ip_address()

        # Create response data as a dictionary
        response_data = {
            'mac_address': mac_address,
            'ip_address': ip_address
        }

        # Convert the response data to JSON format
        response_json = json.dumps(response_data)
        
        # Calculate CRC-16 checksum
        crc = calculate_crc(response_json)

        # Append CRC to the response data
        response_data['crc'] = crc

        # Convert the updated response data to JSON format
        response_json = json.dumps(response_data)


        print(f"Sending response: {response_json} to {addr}")

        # Send response back to sender
        server_socket.sendto(response_json.encode('utf-8'), addr)

        # # Create response message
        # response_message = f"MAC: {mac_address}, IP: {ip_address}\n"
        # print(f"Sending response: {response_message} to {addr}")

        # # Send response back to sender
        # server_socket.sendto(response_message.encode('utf-8'), addr)

if __name__ == "__main__":
    main()


