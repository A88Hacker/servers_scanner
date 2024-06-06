import requests 
from bs4 import BeautifulSoup
import json
import time

class ExtractInfoFromPage:
    def __init__(self, url: dict) -> None:
        self.url_dic = url

    def get_cve_json(self):
        self.json_links = {} 
        button = {}
        for port, url in self.url_dic.items():
            for u in url:                       
                    response1 = requests.get(u)
                    soup = BeautifulSoup(response1.text, 'lxml')
                    button = soup.find('a', class_= "MuiButtonBase-root MuiButton-root MuiButton-outlined MuiButton-outlinedPrimary MuiButton-sizeMedium MuiButton-outlinedSizeMedium MuiButton-fullWidth MuiButton-root MuiButton-outlined MuiButton-outlinedPrimary MuiButton-sizeMedium MuiButton-outlinedSizeMedium MuiButton-fullWidth css-1l09396-Score-json")
                    try:
                        if port not in  self.json_links:
                            self.json_links[port] = ["https://vulners.com" + button.get('href')]
                        else:
                                self.json_links[port].append("https://vulners.com" + button.get('href'))
                    except:
                         pass


    # def get_info_from_json(self):
    #     self.get_cve_json()
    #     for port, js_link_lst in self.json_links.items():
    #         print("-" * 20 + f'Vulnalabilities for {port} port' + "-" * 20)
    #         for js_link in js_link_lst[:40] if len(js_link_lst) >=40 else js_link_lst:
    #             rp = requests.get(js_link)
    #             js_text = json.loads(rp.text)
    #             try:
    #                 for cve, info in js_text['data']['documents'].items():
    #                     try:
    #                         print(f'CVE Name: {cve} \n')
    #                         print(f'Description of valuability: {info["description"]}\n')
    #                         print(f'Published: {info["published"]}\n')
    #                         print(f'Last modified: {info["modified"]}\n')

    #                         if '2015' in js_link:
    #                             print('-' * 10 + "Next CVE" + '-' * 10 + '\n')
    #                             continue
                            
    #                         print('-' * 17 + 'CVSS 3 statictic' + '-' * 17)
    #                         print(f'AttackVector: {info["cvss3"]["cvssV3"]["attackVector"]}')
    #                         print(f'AttackComplexity: {info["cvss3"]["cvssV3"]["attackComplexity"]}')
    #                         print(f'PrivilegesRequired: {info["cvss3"]["cvssV3"]["privilegesRequired"]}')
    #                         print(f'UserInteraction: {info["cvss3"]["cvssV3"]["userInteraction"]}')
    #                         print(f'Scope: {info["cvss3"]["cvssV3"]["scope"]}')
    #                         print(f'ConfidentialityImpact: {info["cvss3"]["cvssV3"]["confidentialityImpact"]}')
    #                         print(f'IntegrityImpact: {info["cvss3"]["cvssV3"]["integrityImpact"]}')
    #                         print(f'AvailabilityImpact: {info["cvss3"]["cvssV3"]["availabilityImpact"]}')
    #                         print(f'Basic Hazard Assessment: {info["cvss3"]["cvssV3"]["baseScore"]} from 10\n \n')
    #                         print('-' * 10 + "Next CVE" + '-' * 10 + '\n')
    #                     except:
    #                         continue
    #             except:
    #                  continue

    def get_info_from_json(self, add_info, filename="result.txt"):
            self.get_cve_json()
            report = add_info
            for port, js_link_lst in self.json_links.items():
                report += "-" * 20 + f'Vulnerabilities for {port} port' + "-" * 20 + "\n"
                for js_link in js_link_lst[:40] if len(js_link_lst) >= 40 else js_link_lst:
                    rp = requests.get(js_link)
                    js_text = json.loads(rp.text)
                    try:
                        for cve, info in js_text['data']['documents'].items():
                            try:
                                report += f'CVE Name: {cve} \n'
                                report += f'Description of vulnerability: {info["description"]}\n'
                                report += f'Published: {info["published"]}\n'
                                report += f'Last modified: {info["modified"]}\n'

                                if '2015' in js_link:
                                    report += '-' * 10 + "Next CVE" + '-' * 10 + '\n'
                                    continue
                                
                                report += '-' * 17 + 'CVSS 3 statistics' + '-' * 17 + "\n"
                                report += f'AttackVector: {info["cvss3"]["cvssV3"]["attackVector"]}\n'
                                report += f'AttackComplexity: {info["cvss3"]["cvssV3"]["attackComplexity"]}\n'
                                report += f'PrivilegesRequired: {info["cvss3"]["cvssV3"]["privilegesRequired"]}\n'
                                report += f'UserInteraction: {info["cvss3"]["cvssV3"]["userInteraction"]}\n'
                                report += f'Scope: {info["cvss3"]["cvssV3"]["scope"]}\n'
                                report += f'ConfidentialityImpact: {info["cvss3"]["cvssV3"]["confidentialityImpact"]}\n'
                                report += f'IntegrityImpact: {info["cvss3"]["cvssV3"]["integrityImpact"]}\n'
                                report += f'AvailabilityImpact: {info["cvss3"]["cvssV3"]["availabilityImpact"]}\n'
                                report += f'Basic Hazard Assessment: {info["cvss3"]["cvssV3"]["baseScore"]} from 10\n\n'
                                report += '-' * 10 + "Next CVE" + '-' * 10 + '\n'
                            except KeyError as e:
                                report += f'There is no key {e}'
                                continue
                    except:
                        continue

            with open(filename, 'w') as file:
                file.write(report)
                print(f"Scan results saved to {filename}")
            return True
            



    def get_json(self):
        self.get_cve_json()
        return self.__json_text
    


