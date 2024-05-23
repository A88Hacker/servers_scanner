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


    def get_info_from_json(self):
        self.get_cve_json()
        for port, js_link_lst in self.json_links.items():
            print("-" * 20 + f'Vulnalabilities for {port} port' + "-" * 20)
            for js_link in js_link_lst[:20] if len(js_link_lst) >=20 else js_link_lst:
                rp = requests.get(js_link)
                js_text = json.loads(rp.text)
                try:
                    for cve, info in js_text['data']['documents'].items():
                        try:
                            print(f'CVE Name: {cve} \n')
                            print(f'Description of valuability: {info["description"]}\n')
                            print(f'Published: {info["published"]}\n')
                            print(f'Last modified: {info["modified"]}\n')

                            if '2015' in js_link:
                                print('-' * 10 + "Next CVE" + '-' * 10 + '\n')
                                continue
                            
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
                            continue
                except:
                     continue




    def get_json(self):
        self.get_cve_json()
        return self.__json_text
    

e = ExtractInfoFromPage({3333: ['https://vulners.com/prion/PRION:CVE-2015-5600', 'https://vulners.com/cve/CVE-2015-5600', 'https://vulners.com/prion/PRION:CVE-2020-16088', 'https://vulners.com/prion/PRION:CVE-2015-6564', 'https://vulners.com/cve/CVE-2015-6564', 'https://vulners.com/cve/CVE-2018-15919', 'https://vulners.com/cve/CVE-2010-4816', 'https://vulners.com/prion/PRION:CVE-2015-5352', 'https://vulners.com/cve/CVE-2020-14145', 'https://vulners.com/cve/CVE-2015-5352', 'https://vulners.com/prion/PRION:CVE-2015-6563', 'https://vulners.com/cve/CVE-2015-6563'], 80: ['https://vulners.com/packetstorm/PACKETSTORM:176334', 'https://vulners.com/packetstorm/PACKETSTORM:171631', 'https://vulners.com/osv/OSV:BIT-APACHE-2023-25690', 'https://vulners.com/osv/OSV:BIT-APACHE-2022-31813', 'https://vulners.com/osv/OSV:BIT-APACHE-2022-23943', 'https://vulners.com/osv/OSV:BIT-APACHE-2022-22720', 'https://vulners.com/osv/OSV:BIT-APACHE-2021-44790', 'https://vulners.com/osv/OSV:BIT-APACHE-2021-42013', 'https://vulners.com/osv/OSV:BIT-APACHE-2021-41773', 'https://vulners.com/osv/OSV:BIT-APACHE-2021-39275', 'https://vulners.com/osv/OSV:BIT-APACHE-2021-26691', 'https://vulners.com/osv/OSV:BIT-APACHE-2020-11984', 'https://vulners.com/metasploit/MSF:EXPLOIT-MULTI-HTTP-APACHE_NORMALIZE_PATH_RCE-', 'https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-HTTP-APACHE_NORMALIZE_PATH-', 'https://vulners.com/githubexploit/F9C0CD4B-3B60-5720-AE7A-7CC31DB839C5', 'https://vulners.com/githubexploit/F41EE867-4E63-5259-9DF0-745881884D04', 'https://vulners.com/exploitdb/EDB-ID:51193', 'https://vulners.com/exploitdb/EDB-ID:50512', 'https://vulners.com/exploitdb/EDB-ID:50446', 'https://vulners.com/exploitdb/EDB-ID:50406', 'https://vulners.com/githubexploit/E796A40A-8A8E-59D1-93FB-78EF4D8B7FA6', 'https://vulners.com/cve/CVE-2023-25690', 'https://vulners.com/cve/CVE-2022-31813', 'https://vulners.com/cve/CVE-2022-23943', 'https://vulners.com/cve/CVE-2022-22720', 'https://vulners.com/cve/CVE-2021-44790', 'https://vulners.com/cve/CVE-2021-39275', 'https://vulners.com/cve/CVE-2021-26691', 'https://vulners.com/cve/CVE-2017-7679', 'https://vulners.com/cve/CVE-2017-3167', 'https://vulners.com/cnvd/CNVD-2022-73123', 'https://vulners.com/cnvd/CNVD-2022-03225', 'https://vulners.com/cnvd/CNVD-2021-102386', 'https://vulners.com/githubexploit/CC15AE65-B697-525A-AF4B-38B1501CAB49', 'https://vulners.com/githubexploit/C879EE66-6B75-5EC8-AA68-08693C6CCAD1', 'https://vulners.com/githubexploit/B02819DB-1481-56C4-BD09-6B4574297109', 'https://vulners.com/githubexploit/9B4F4E4A-CFDF-5847-805F-C0BAE809DBD5', 'https://vulners.com/githubexploit/8713FD59-264B-5FD7-8429-3251AB5AB3B8', 'https://vulners.com/githubexploit/831E1114-13D1-54EF-BDE4-F655114CDC29', 'https://vulners.com/githubexploit/78787F63-0356-51EC-B32A-B9BD114431C3', 'https://vulners.com/githubexploit/6A0A657E-8300-5312-99CE-E11F460B1DBF', 'https://vulners.com/githubexploit/64D31BF1-F977-51EC-AB1C-6693CA6B58F3', 'https://vulners.com/githubexploit/61075B23-F713-537A-9B84-7EB9B96CF228', 'https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9', 'https://vulners.com/githubexploit/5312D04F-9490-5472-84FA-86B3BBDC8928', 'https://vulners.com/githubexploit/52E13088-9643-5E81-B0A0-B7478BCF1F2C', 'https://vulners.com/githubexploit/495E99E5-C1B0-52C1-9218-384D04161BE4', 'https://vulners.com/githubexploit/3F17CA20-788F-5C45-88B3-E12DB2979B7B', 'https://vulners.com/githubexploit/22DCCD26-B68C-5905-BAC2-71D10DE3F123', 'https://vulners.com/githubexploit/2108729F-1E99-54EF-9A4B-47299FD89FF2', 'https://vulners.com/zdt/1337DAY-ID-39214', 'https://vulners.com/zdt/1337DAY-ID-38427', 'https://vulners.com/zdt/1337DAY-ID-37777', 'https://vulners.com/zdt/1337DAY-ID-36952', 'https://vulners.com/zdt/1337DAY-ID-34882', 'https://vulners.com/packetstorm/PACKETSTORM:127546', 'https://vulners.com/osv/OSV:BIT-APACHE-2021-40438', 'https://vulners.com/osv/OSV:BIT-APACHE-2020-35452', 'https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8', 'https://vulners.com/cve/CVE-2021-40438', 'https://vulners.com/cve/CVE-2020-35452', 'https://vulners.com/cve/CVE-2018-1312', 'https://vulners.com/cve/CVE-2017-15715', 'https://vulners.com/cve/CVE-2016-5387', 'https://vulners.com/cve/CVE-2014-0226', 'https://vulners.com/cnvd/CNVD-2022-03224', 'https://vulners.com/githubexploit/AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C', 'https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2']})
e.get_info_from_json()
