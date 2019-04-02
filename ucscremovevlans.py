import sys
import csv

filename = str(sys.argv[1])

print "clear"
print "Import-Module CiscoUcsPS"
print "\n"
print "$ucsc = \"192.168.224.70\""
print "$user = \"admin\""
print "$password = \"C1sc0123\" | ConvertTo-SecureString -AsPlainText -Force"
print "$primaryVnic = \"ludt-data-a\""
print "$secondaryVnic = \"ludt-data-b\""
print "\n"
print "$cred = New-Object system.Management.Automation.PSCredential ($user,$password)"
print "Connect-UcsCentral $ucsc -Credential $cred"
print "\n"

print "Start-UcsCentralTransaction"
print "$mo = Get-UcsCentralOrg -Level root | Add-UcsCentralVnicTemplate -ModifyPresent  -Name $primaryVnic"

with open(filename, 'rb') as csvfile:
        contents = csv.reader(csvfile,delimiter=',')
        sequence = 0
        for vlan in contents:
                sequence+=1
                print "$mo_{} =  $mo | Get-UcsCentralVnicInterface -Name \"u-tenant4-{}-v{}\" | Remove-UcsCentralVnicInterface".format(sequence,vlan[1],vlan[0])

print "Complete-UcsCentralTransaction"
print "Start-UcsCentralTransaction"
print "$mo = Get-UcsCentralOrg -Level root | Add-UcsCentralVnicTemplate -ModifyPresent  -Name $secondaryVnic"

with open(filename, 'rb') as csvfile:
        contents = csv.reader(csvfile,delimiter=',')
        sequence = 0
        for vlan in contents:
                sequence+=1
                print "$mo_{} =  $mo | Get-UcsCentralVnicInterface -Name \"u-tenant4-{}-v{}\" | Remove-UcsCentralVnicInterface".format(sequence,vlan[1],vlan[0])

print "Complete-UcsCentralTransaction"
print "Disconnect-UcsCentral"
