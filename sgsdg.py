import pprint
import nmap 

host = 'scanme.nmap.org'
scanner = nmap.PortScanner()
# scan_raw_result = scanner.scan(hosts=host, arguments='-A --script=vulners')
# pprint.pprint(scan_raw_result)
#print(scan_raw_result['scan']['156.17.75.60']['tcp'][80]['product'])
# print(scanner.scan())
dic = {}
dic[1].append(5)