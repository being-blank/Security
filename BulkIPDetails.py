#importing liberaries
from tqdm import tqdm
import time
from ipwhois import IPWhois
import csv


#reading csv file
filename = input()
csv_file = open(filename,"r")
csv_reader = csv.reader(csv_file,delimiter=',')


#initializing variables
ip_add = []
head_ing = ['ip','asn_register','asn','asn_cidr','asn_country_code','asn_date','asn_description','network_handle','network_status','network_ipv','network_type','network_name','network_country','network_parent_handle']


#finding IP details
print("Scanning in progress...")
for row in tqdm(csv_reader):
    ip_add.append(row)
    obj = IPWhois(row[0])
    res = obj.lookup_rdap(asn_methods=["whois"])
    row.append(res['asn_registry'])
    row.append(res['asn'])
    row.append(res['asn_cidr'])
    row.append(res['asn_country_code'])
    row.append(res['asn_date'])
    row.append(res['asn_description'])
    row.append(res['network']['handle'])
    row.append(res['network']['status'])
    row.append(res['network']['ip_version'])
    row.append(res['network']['type'])
    row.append(res['network']['name'])
    row.append(res['network']['country'])
    row.append(res['network']['parent_handle'])
    time.sleep(0.5)

print("Scan Complete.")
print("Writing in Progress...")


#creating csv file
with open("result.csv","w") as csvf:
    csvwriter = csv.writer(csvf)
    csvwriter.writerow(head_ing)
    csvwriter.writerows(ip_add)
print("Task Completed")
