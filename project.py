import nmap 
import re
import stuff

class OpenHosts:
    def __init__(self) -> None:     
        self.scanner = nmap.PortScanner()


    def __find_hosts(self, ip_addresses = '192.168.1.0/24'):
        self.scanner.scan(ip_addresses, arguments='-sP -PE -PA21, 23, 80, 3389')
        hosts_list = [(x, self.scanner[x].state()) for x in self.scanner.all_hosts()] 
        return hosts_list
    
    def get_hosts_list(self, ip_addresses = '192.168.1.0/24'):
        self.__hosts_list = self.__find_hosts(ip_addresses)
        for host, status in self.__hosts_list:
            print(f'{host}: {status}')



class OpenPorts:
    def __init__(self) -> None:
        self.__scanner = nmap.PortScanner()


    def discover_open_ports(self, server = '192.168.1.0/24'):
         self.p = self.__scanner.scan(server, '22-1000', arguments='-v -n -A')
         return self.p



    def get_open_ports(self, server):
        self.discover_open_ports(server = server)
        for host in self.__scanner.all_hosts():
            print('-----------------------------------------------------')
            print(f'Host : {host} {self.__scanner[host].hostname()}')
            print(f'State : {self.__scanner[host].state()}')
            print(f'System : {self.__scanner[host]["tcp"]["product"]}')
            # print(f'Version : {self.__scanner[host]["tcp"][80]["version"]}')
            for pr in self.__scanner[host].all_protocols():
                print('------')
                print(f"Protocol : {pr} ")
                ports = self.__scanner[host][pr].keys()
                for p in sorted(ports):
                    print(f'Port: {p}  State: {self.__scanner[host][pr][p]["state"]}')


   
class InfoHost:
    def __init__(self, target) -> None:
        self.__target = target 
        self.__scanner = nmap.PortScanner()
        self.__scan_result = self.__scanner.scan(hosts=self.__target, arguments='-A --script=vulners')

    # def scan_host(self):
    #     for host, result in self.__scan_result['scan'].items():
    #         if result['status']['state'] == 'up':
    #             print(f'Host: {host} - State: up')
    #             print(' ' * 17 + "Server's details:" + ' ' * 17)
    #             print()
    #             for port in result['tcp']:
    #                 print('-' * 17 + "Port's details:" + '-' * 17)
    #                 print(f"Port number: {port}")
    #                 print(f"Extra info: {result['tcp'][port]['extrainfo']}")
    #                 print(f"Name: {result['tcp'][port]['name']}")
    #                 print(f"Service: {result['tcp'][port]['product']}")
    #                 print(f"Version: {result['tcp'][port]['version']}")

    def scan_host(self, filename="scan_results.txt"):
        with open(filename, 'w') as file:
            for host, result in self.__scan_result['scan'].items():
                if result['status']['state'] == 'up':
                    file.write(f'Host: {host} - State: up\n')
                    file.write(' ' * 17 + "Server's details:" + ' ' * 17 + '\n\n')
                    for port in result['tcp']:
                        file.write('-' * 17 + "Port's details:" + '-' * 17 + '\n')
                        file.write(f"Port number: {port}\n")
                        file.write(f"Extra info: {result['tcp'][port]['extrainfo']}\n")
                        file.write(f"Name: {result['tcp'][port]['name']}\n")
                        file.write(f"Service: {result['tcp'][port]['product']}\n")
                        file.write(f"Version: {result['tcp'][port]['version']}\n\n")
        print(f"Scan results saved to {filename}")

    def make_dic_links(self):
        self.__vuln_links = {}
        for host, result in self.__scan_result['scan'].items():
            if result['status']['state'] == 'up':
                for port in result['tcp']:
                    try:
                        vulners_str = result['tcp'][port]['script']['vulners']
                        self.__vuln_links[port] = re.findall(r'https://[^\s]+', vulners_str)
                        

                    except:
                        pass

    def get_links(self):
        self.make_dic_links()
        return self.__vuln_links
  
            # for port, info in result['tcp'].items():
            #     print(f"Port: {port} \n --- Additional info: --- \n {info['extrainfo']} \n Name: {info['name']} \n Service: {info['product']} \n Version: {info['version']} \n ------------------------------------------ \n")
            


        

def start_scan(target):
    inf = InfoHost(target)
    inf.scan_host()
    links_for_pars = inf.get_links()
    e = stuff.ExtractInfoFromPage(links_for_pars)
    e.get_info_from_json()





start_scan('rezka.ag')