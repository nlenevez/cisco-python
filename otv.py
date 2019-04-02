import sys

vlanstring = input("Please enter Vlan ID range seperated by commas: ")
vlans = [int (n) for n in vlanstring.split(',')]

print("! BDR1.TA / BDR3.SY4")
print("interface Port-Channel16")
for vlan in vlans:
	print(" service instance {} ethernet".format(vlan))
	print("  encapsulation dot1q {}".format(vlan))
	print("  mac access-group otv_fhrp in")
	print("  snmp ifindex persist")
	print("  bridge-domain {}".format(vlan))
	print(" !")
print("!")
print("interface Overlay1")
for vlan in vlans:
        print(" service instance {} ethernet".format(vlan))
        print("  encapsulation dot1q {}".format(vlan))
        print("  snmp ifindex persist")
        print("  bridge-domain {}".format(vlan))
        print(" !")
print ("!")
print("end\n")
print("! BDR2.TA / BDR4.SY4")
print("interface Port-Channel17")
for vlan in vlans:
        print(" service instance {} ethernet".format(vlan))
        print("  encapsulation dot1q {}".format(vlan))
        print("  mac access-group otv_fhrp in")
        print("  snmp ifindex persist")
        print("  bridge-domain {}".format(vlan))
        print(" !")
print("!") 
print("interface Overlay1")
for vlan in vlans:
        print(" service instance {} ethernet".format(vlan))
        print("  encapsulation dot1q {}".format(vlan))
        print("  snmp ifindex persist")
        print("  bridge-domain {}".format(vlan))
        print(" !")
print ("!")
print("end\n")
print("! Core Switches")
print ("")
for vlan in vlans:
	print("mac address-table aging-time 600 vlan {}".format(vlan)) 
print ("!") 
print("interface range Port-Channel16-17")
print(" switchport trunk allowed vlan add {}".format(vlanstring))
print("!")

