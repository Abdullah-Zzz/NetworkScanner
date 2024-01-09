from scapy.all import *
import concurrent.futures

try:

    ip_input=input("Enter IP or IP pool (192.168.0.0/24): ")


    def online_checker(ip):
        
        packet=IP(dst=ip) / ICMP()

        response=sr1(packet, timeout=1, verbose=0 )
        
        if response and response.haslayer(ICMP):
            return f"{ip} is online. "
        else:
            return f"{ip} is offline. "


    def parallel_host_checker(ip_addresses):
        
        live_hosts=[]

        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            checking_hosts={executor.submit(online_checker, ip):ip for ip in ip_addresses}
            for future in concurrent.futures.as_completed(checking_hosts):
                result=future.result()
                live_hosts.append(result)
        
        if "/" in ip_input or "-" in ip_input:
            live_hosts=[host for host in live_hosts if "offline" not in host]
        
        print(live_hosts)


    if "/" in ip_input:
        ip_for_pool, subnet_for_pool=ip_input.split("/")
        ip_for_pool=ip_for_pool.split(".")
        ip_addresses=[f"{ip_for_pool[0]}.{ip_for_pool[1]}.{ip_for_pool[2]}.{i}" for i in range(1, 255)]
        parallel_host_checker(ip_addresses)

    elif "-" in ip_input:
        ip_for_range, subnet_for_range=ip_input.split("-")
        ip_for_range=ip_for_range.split(".")
        ip_addresses=[f"{ip_for_range[0]}.{ip_for_range[1]}.{ip_for_range[2]}.{i}" for i in range(int(ip_for_range[3]), int(subnet_for_range)+1)]
        parallel_host_checker(ip_addresses)
        

    else:
        result=online_checker(ip_input)
        print(result)


except Scapy_Exception as se :
    print(f"Error: {se}")
except PermissionError as p :
    print(f"Error: {p}")
except OSError as o :
    print(f"Error: {o}")
except Exception as e :
    print(f"Error: {e}")


                



