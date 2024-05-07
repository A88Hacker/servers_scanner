import requests 
from bs4 import BeautifulSoup
import json
import time

class ExtractInfoFromPage:
    def __init__(self, url) -> None:
        self.url = url

    def get_cve_json(self):
        try:
            response1 = requests.get(self.url)
            soup = BeautifulSoup(response1.text, 'lxml')
            button = soup.find('a', class_= "MuiButtonBase-root MuiButton-root MuiButton-outlined MuiButton-outlinedPrimary MuiButton-sizeMedium MuiButton-outlinedSizeMedium MuiButton-fullWidth MuiButton-root MuiButton-outlined MuiButton-outlinedPrimary MuiButton-sizeMedium MuiButton-outlinedSizeMedium MuiButton-fullWidth css-1l09396-Score-json")
            link = 'https://vulners.com' + button.get('href')
        except AttributeError:
            print("None value, repeat in 3 sec...")
            time.sleep(3)
            link = 'https://vulners.com' + button.get('href') 
        response2 = requests.get(link)
        self.__json_text = json.loads(response2.text)


    def get_info_from_json(self):
        self.get_cve_json()
        for cve, info in self.__json_text['data']['documents'].items():
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
            print(f'Basic Hazard Assessment: {info["cvss3"]["cvssV3"]["baseScore"]} from 10')




    def get_json(self):
        self.get_cve_json()
        return self.__json_text

e = ExtractInfoFromPage('https://vulners.com/osv/OSV:BIT-APACHE-2020-13938')
e.get_info_from_json()