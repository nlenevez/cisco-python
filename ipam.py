import sys
import csv

filename = str(sys.argv[1])

with open(filename, 'rb') as csvfile:
        contents = csv.reader(csvfile,delimiter=',')
        for vlan in contents:
                print "INSERT INTO vlans(domainId,name,number,description) VALUES(4,'{}',{},'Tenant4(UMPE)');".format(vlan[2],vlan[0])

