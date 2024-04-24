# Jason Liu - jieliu0508@gmail.com

from netmiko import ConnectHandler
from getpass import getpass
import socket
import time

#hardcode ASA access
# net_device = {
#     "device_type":"cisco_asa",
#     "ip":"",
#     "username":"admin",
#     "password":"Admin123",
#     "secret":"Admin123",
#     "port":22,
# }

# asa_ip = input("Please input ASA IP Address: ")
asa_username = input("Please input ASA Username: ")
asa_password = getpass()
asa_secret = getpass(prompt="Secret:")

net_device = {
    "device_type":"cisco_asa",
    "ip":"",
    "username":asa_username,
    "password":asa_password,
    "secret":asa_secret,
    "port":22,
}

SERVER = ""
PORT = 6789

SERVER = socket.gethostbyname(socket.gethostname())



serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSocket.bind((SERVER, PORT))
print(f"\nServer {SERVER} is listening on UDP port {PORT}......**** Please make sure Windows firewall is allowed the connection ****")


log_num = 0
attacker_ip=""
failures_to_shun = int(input("\nHow many repeated login failures from the same IP need be shunned? please input a number: "))
print(f"\nOkay, you want to shun repeated {failures_to_shun} login failure, I am listening now ......")
failed_times = 0
attacker_ip_list=[]   # a list store attacker's IP
start=time.time()
    


while True: #run forever
    data, addr = serverSocket.recvfrom(1024)
    if "113005" in str(data):
        net_device["ip"]= addr[0]
        print(f'\n{data.decode()}')
        log=  str(data)
        cur = time.time()
        if cur-start > 3600 and len(attacker_ip_list) > 0:
            print("Last login failure is one hour again, creating a new attacker IP list!")
            attacker_ip_list.clear() 
        attacker_ip = log[log.find("IP")+5:-3]
        if attacker_ip in attacker_ip_list:      #if the attacker IP is already in the list
            attacker_ip_list.append(attacker_ip)  
            if len(attacker_ip_list) == failures_to_shun:  # reach failure threshold
                print(f"!!!!!! {attacker_ip}  has {failures_to_shun} failed login, requesting ASA {addr[0]} to shun the IP......")
                ssh_conn = ConnectHandler(**net_device)
                shun_com = "shun " + attacker_ip
                output = ssh_conn.send_command(shun_com)
                print(output)

                #A object group called "Attacker-IPs" used in control plane ACL to block attackers, uncomment follow 3 linesif needed.
                # commands = ["object-group network Attacker-IPs",f"network-object host {attacker_ip}"]
                # ssh_conn.send_config_set(commands)
                # print(f"\n{attacker_ip} is also added to object group Attacker-IPs"  )
                
                print("\nScript is listening for more login failures..."  )

                ssh_conn.disconnect() 
                attacker_ip_list.clear()
                start = time.time()
                
            else:
                print(f"ASA {addr[0]} see {len(attacker_ip_list)} login failures from {attacker_ip}." )
                start = time.time()
        
        else:                                     # if it is a new attacker IP, clear the list and add new IP to the list
            print(f"ASA {addr[0]} see a new login failure from {attacker_ip}. " )
            attacker_ip_list.clear()           
            attacker_ip_list.append(attacker_ip) 
            start = time.time()
            
         


