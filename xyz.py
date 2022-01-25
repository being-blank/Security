#importing liberaries
from tqdm import tqdm
import time
from ipwhois import IPWhois
import csv


#reading csv file
filename = input()
csv_file = open(filename,"r")
csv_reader = csv.reader(csv_file,delimiter=',')
ip_add = []
head_ing = ['IP','NetName']

print("Scanning in progress...")
for row in tqdm(csv_reader):
    ip_add.append(row)
    obj = IPWhois(row[0])
    res = obj.lookup_rdap(asn_methods=["whois"])
    row.append(res['network']['name'])
    time.sleep(0.5)

print("Scan Complete.")
print("Writing in Progress...")


#writing csv file
with open("result.csv","w") as csvf:
    csvwriter = csv.writer(csvf)
    csvwriter.writerow(head_ing)
    csvwriter.writerows(ip_add)

print("Completed")