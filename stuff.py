import requests 
from bs4 import BeautifulSoup
import json
import time

class ExtractInfoFromPage:
    def __init__(self, url: dict) -> None:
        self.url_dic = url

    def get_cve_json(self):
        self.json_links = {} 
        button = []
        for port, url in self.url_dic.items():
            for u in url:
                while len(button) == 0:
                    try:
                        response1 = requests.get(u)
                        soup = BeautifulSoup(response1.text, 'lxml')
                        button = soup.find('a', class_= "MuiButtonBase-root MuiButton-root MuiButton-outlined MuiButton-outlinedPrimary MuiButton-sizeMedium MuiButton-outlinedSizeMedium MuiButton-fullWidth MuiButton-root MuiButton-outlined MuiButton-outlinedPrimary MuiButton-sizeMedium MuiButton-outlinedSizeMedium MuiButton-fullWidth css-1l09396-Score-json")
                        if port not in  self.json_links:
                            self.json_links[port] = ["https://vulners.com" + button.get('href')]
                        else:
                            self.json_links[port].append("https://vulners.com" + button.get('href'))
                    except AttributeError:
                        print("None value")
                        continue
            # response2 = requests.get(link)
            # self.__json_text = json.loads(response2.text)


    def get_info_from_json(self):
        self.get_cve_json()
        for port, js_link_lst in self.json_links.items():
            print("-" * 20 + f'Vulnalabilities for {port} port' + "-" * 20)
            for js_link in js_link_lst:
                rp = requests.get(js_link)
                js_text = json.loads(rp.text)
                try:
                    for cve, info in js_text['data']['documents'].items():
                        print(f'CVE Name: {cve} \n')
                        print(f'Description of valuability: {info["description"]}\n')
                        print(f'Published: {info["published"]}\n')
                        print(f'Last modified: {info["modified"]}\n')

                        print('-' * 17 + 'CVSS 3 statictic' + '-' * 17)
                        print(f'AttackVector: {info["cvss3"]["cvssV3"]["attackVector"]}')
                        print(f'AttackComplexity: {info["cvss3"]["cvssV3"]["attackComplexity"]}')
                        print(f'PrivilegesRequired: {info["cvss3"]["cvssV3"]["privilegesRequired"]}')
                        print(f'UserInteraction: {info["cvss3"]["cvssV3"]["userInteraction"]}')
                        print(f'Scope: {info["cvss3"]["cvssV3"]["scope"]}')
                        print(f'ConfidentialityImpact: {info["cvss3"]["cvssV3"]["confidentialityImpact"]}')
                        print(f'IntegrityImpact: {info["cvss3"]["cvssV3"]["integrityImpact"]}')
                        print(f'AvailabilityImpact: {info["cvss3"]["cvssV3"]["availabilityImpact"]}')
                        print(f'Basic Hazard Assessment: {info["cvss3"]["cvssV3"]["baseScore"]} from 10\n \n')
                        print('-' * 10 + "Next CVE" + '-' * 10 + '\n')
                except:
                    pass




    def get_json(self):
        self.get_cve_json()
        return self.__json_text

# e = ExtractInfoFromPage({22: [ 'https://vulners.com/cve/CVE-2019-9640', 'https://vulners.com/cve/CVE-2019-0192'] , 80:['https://vulners.com/cve/CVE-2019-17567'] })
# e.get_info_from_json()
# e.get_cve_json()