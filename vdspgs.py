import sys
import csv

filename = str(sys.argv[1])

with open(filename, 'rb') as csvfile:
        contents = csv.reader(csvfile,delimiter=',')
        for vlan in contents:
                print "Get-VDSwitch -name \"ludtisznvds002\" | New-VDPortGroup -name \"{}\" -vlanid {}".format(vlan[2],vlan[0])
