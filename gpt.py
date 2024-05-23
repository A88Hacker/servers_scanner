import tkinter as tk
from tkinter import messagebox
import nmap
import re
import requests
from bs4 import BeautifulSoup
import json

class InfoHost:
    def __init__(self, target) -> None:
        self.__target = target 
        self.__scanner = nmap.PortScanner()
        self.__scan_result = self.__scanner.scan(hosts=self.__target, arguments='-A --script=vulners')

    def scan_host(self):
        host_info = ""
        for host, result in self.__scan_result['scan'].items():
            if result['status']['state'] == 'up':
                host_info += f'Host: {host} - State: up\n'
                host_info += ' ' * 17 + "Server's details:" + ' ' * 17 + '\n\n'
                for port in result['tcp']:
                    host_info += '-' * 17 + "Port's details:" + '-' * 17 + '\n'
                    host_info += f"Port number: {port}\n"
                    host_info += f"Extra info: {result['tcp'][port]['extrainfo']}\n"
                    host_info += f"Name: {result['tcp'][port]['name']}\n"
                    host_info += f"Service: {result['tcp'][port]['product']}\n"
                    host_info += f"Version: {result['tcp'][port]['version']}\n\n'
        return host_info

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

def start(target):
    inf = InfoHost(target)
    scan_info = inf.scan_host()
    links_for_pars = inf.get_links()
    e = ExtractInfoFromPage(links_for_pars)
    cve_info = e.get_info_from_json()
    return scan_info + "\n" + cve_info

class ExtractInfoFromPage:
    def __init__(self, url: dict) -> None:
        self.url_dic = url

    def get_cve_json(self):
        self.json_links = {}
        for port, url in self.url_dic.items():
            for u in url:                       
                response1 = requests.get(u)
                soup = BeautifulSoup(response1.text, 'lxml')
                button = soup.find('a', class_= "MuiButtonBase-root MuiButton-root MuiButton-outlined MuiButton-outlinedPrimary MuiButton-sizeMedium MuiButton-outlinedSizeMedium MuiButton-fullWidth MuiButton-root MuiButton-outlined MuiButton-outlinedPrimary MuiButton-sizeMedium MuiButton-outlinedSizeMedium MuiButton-fullWidth css-1l09396-Score-json")
                try:
                    if port not in self.json_links:
                        self.json_links[port] = ["https://vulners.com" + button.get('href')]
                    else:
                        self.json_links[port].append("https://vulners.com" + button.get('href'))
                except:
                    pass

    def get_info_from_json(self):
        self.get_cve_json()
        cve_info = ""
        for port, js_link_lst in self.json_links.items():
            cve_info += "-" * 20 + f'Vulnerabilities for {port} port' + "-" * 20 + "\n"
            for js_link in js_link_lst[:20] if len(js_link_lst) >= 20 else js_link_lst:
                rp = requests.get(js_link)
                js_text = json.loads(rp.text)
                try:
                    for cve, info in js_text['data']['documents'].items():
                        try:
                            cve_info += f'CVE Name: {cve}\n'
                            cve_info += f'Description of vulnerability: {info["description"]}\n'
                            cve_info += f'Published: {info["published"]}\n'
                            cve_info += f'Last modified: {info["modified"]}\n'
                            if '2015' in js_link:
                                cve_info += '-' * 10 + "Next CVE" + '-' * 10 + '\n'
                                continue
                            cve_info += '-' * 17 + 'CVSS 3 statistics' + '-' * 17 + "\n"
                            cve_info += f'AttackVector: {info["cvss3"]["cvssV3"]["attackVector"]}\n'
                            cve_info += f'AttackComplexity: {info["cvss3"]["cvssV3"]["attackComplexity"]}\n'
                            cve_info += f'PrivilegesRequired: {info["cvss3"]["cvssV3"]["privilegesRequired"]}\n'
                            cve_info += f'UserInteraction: {info["cvss3"]["cvssV3"]["userInteraction"]}\n'
                            cve_info += f'Scope: {info["cvss3"]["cvssV3"]["scope"]}\n'
                            cve_info += f'ConfidentialityImpact: {info["cvss3"]["cvssV3"]["confidentialityImpact"]}\n'
                            cve_info += f'IntegrityImpact: {info["cvss3"]["cvssV3"]["integrityImpact"]}\n'
                            cve_info += f'AvailabilityImpact: {info["cvss3"]["cvssV3"]["availabilityImpact"]}\n'
                            cve_info += f'Base Score: {info["cvss3"]["cvssV3"]["baseScore"]} from 10\n\n'
                            cve_info += '-' * 10 + "Next CVE" + '-' * 10 + '\n'
                        except:
                            continue
                except:
                    continue
        return cve_info

def scan():
    url = url_entry.get()
    if url:
        result = start(url)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, result)
    else:
        messagebox.showwarning("Input error", "Please enter a valid URL.")

# GUI
root = tk.Tk()
root.title("Vulnerability Scanner")

# URL Entry
tk.Label(root, text="Enter URL:").pack(pady=5)
url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=5)

# Scan Button
scan_button = tk.Button(root, text="Scan", command=scan)
scan_button.pack(pady=10)

# Result Text
result_text = tk.Text(root, height=25, width=100)
result_text.pack(pady=10)

root.mainloop()
