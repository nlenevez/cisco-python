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
print "$mo = Get-UcsCentralOrgDomainGroup -Name \"root\" | Get-UcsCentralOrgDomainGroup -Name \"LUDT\" -LimitScope | Get-UcsCentralFabricEp -LimitScope | Get-UcsCentralLanCloud"

with open(filename, 'rb') as csvfile:
        contents = csv.reader(csvfile,delimiter=',')
        sequence = 0
        for vlan in contents:
                sequence+=1
                print "$mo_{} = $mo | Add-UcsCentralVlan -Id {} -Name \"u-tenant4-{}-v{}\"".format(sequence,vlan[0],vlan[1],vlan[0])

print "Complete-UcsCentralTransaction"

with open(filename, 'rb') as csvfile:
        contents = csv.reader(csvfile,delimiter=',')
        for vlan in contents:
                print "Get-UcsCentralOrg -Level root | Add-UcsCentralFabricVlanReq -Name \"u-tenant4-{}-v{}\"".format(vlan[1],vlan[0])

print "Start-UcsCentralTransaction"
print "$mo = Get-UcsCentralOrg -Level root | Add-UcsCentralVnicTemplate -ModifyPresent  -Name $primaryVnic"

with open(filename, 'rb') as csvfile:
        contents = csv.reader(csvfile,delimiter=',')
        sequence = 0
        for vlan in contents:
                sequence+=1
                print "$mo_{} =  $mo | Add-UcsCentralVnicInterface -Name \"u-tenant4-{}-v{}\"".format(sequence,vlan[1],vlan[0])

print "Complete-UcsCentralTransaction"
print "Start-UcsCentralTransaction"
print "$mo = Get-UcsCentralOrg -Level root | Add-UcsCentralVnicTemplate -ModifyPresent  -Name $secondaryVnic"

with open(filename, 'rb') as csvfile:
        contents = csv.reader(csvfile,delimiter=',')
        sequence = 0
        for vlan in contents:
                sequence+=1
                print "$mo_{} =  $mo | Add-UcsCentralVnicInterface -Name \"u-tenant4-{}-v{}\"".format(sequence,vlan[1],vlan[0])

print "Complete-UcsCentralTransaction"
print "Disconnect-UcsCentral"
