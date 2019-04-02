import sys

vrf = input("Please enter the VRF name: ")
rd = input("Please enter the desired RT: ")

myAsn = "38826"
vrfAsn = "65{}".format(rd)
rt = "38826:{}".format(rd)
loopbackInt = "Loopback{}".format(rd)
core1Loopback = "10.8.{}.254".format(rd)
core2Loopback = "10.8.{}.253".format(rd)
core3Loopback = "10.8.{}.252".format(rd)
core4Loopback = "10.8.{}.251".format(rd)
vpn1Loopback = "10.8.{}.250".format(rd)
vpn2Loopback = "10.8.{}.249".format(rd)
peeringInt = "Vlan{}".format(rd)
peeringIp = "10.8.{}.1".format(rd)
bgpPeer = "10.8.{}.6".format(rd)
peeringSubnet = "255.255.255.248"
n1kUplinkPortProfile = "n1k-eth-uplink-trunk"

vrfDefinition = (
"vrf definition {}\n"
" rd {}\n"
" !\n"
" address-family ipv4\n"
"  route-target export {}\n"
"  route-target import {}\n"
"  route-target import {}:101\n"
" exit-address-family\n"
"!\n"
"vrf definition Infinite-Monitoring\n"
" address-family ipv4\n"
"  route-target import {}\n"
" exit-address-family\n"
"!"
).format(vrf,rt,rt,rt,myAsn,rt)

n1kPortProfileDefinition = (
"port-profile type vethernet {}\n"
" switchport mode access\n"
" switchport access vlan {}\n"
" pinning id 1\n"
" no shutdown\n"
" state enabled\n"
" vmware port-group Vlan{:0>4}_{}"
).format(peeringInt,rd,rd,vrf)

print("! CORE1.TA")
print("{}".format(vrfDefinition))
print("interface {}".format(loopbackInt))
print(" vrf forwarding {}".format(vrf))
print(" ip address {} 255.255.255.255".format(core1Loopback))
print("!")
print("router bgp {}".format(myAsn))
print(" address-family ipv4 vrf {}".format(vrf))
print("  bgp router-id {}".format(core1Loopback))
print("  redistribute connected")
print("  redistribute static")
print("  neighbor {} remote-as {}".format(bgpPeer,vrfAsn))
print("  neighbor {} activate".format(bgpPeer))
print(" exit-address-family")
print("!")
print("vlan {}".format(rd))
print(" name {}".format(vrf))
print("exit")
print("!")
print("interface {}".format(peeringInt))
print(" ip address {} {}".format(peeringIp,peeringSubnet))
print(" no shutdown")
print("!")
print("")

print("! CORE2.TA")
print("{}".format(vrfDefinition))
print("interface {}".format(loopbackInt))
print(" vrf forwarding {}".format(vrf))
print(" ip address {} 255.255.255.255".format(core2Loopback))
print("!")
print("router bgp {}".format(myAsn))
print(" address-family ipv4 vrf {}".format(vrf))
print("  bgp router-id {}".format(core2Loopback)) 
print("  redistribute connected")  
print("  redistribute static")  
print(" exit-address-family")
print("!")
print("")

print("! CORE3.SY4")
print("{}".format(vrfDefinition))
print("interface {}".format(loopbackInt))
print(" vrf forwarding {}".format(vrf))
print(" ip address {} 255.255.255.255".format(core3Loopback))
print("!")
print("router bgp {}".format(myAsn))
print(" address-family ipv4 vrf {}".format(vrf))
print("  bgp router-id {}".format(core3Loopback)) 
print("  redistribute connected")  
print("  redistribute static")  
print(" exit-address-family")
print("!")
print("")

print("! CORE4.SY4")
print("{}".format(vrfDefinition))
print("interface {}".format(loopbackInt))
print(" vrf forwarding {}".format(vrf))
print(" ip address {} 255.255.255.255".format(core4Loopback))
print("!")
print("router bgp {}".format(myAsn))
print(" address-family ipv4 vrf {}".format(vrf))
print("  bgp router-id {}".format(core4Loopback)) 
print("  redistribute connected")  
print("  redistribute static")  
print(" exit-address-family")
print("!") 
print("")

print("! VPN1.TA")
print("{}".format(vrfDefinition))
print("interface {}".format(loopbackInt))
print(" vrf forwarding {}".format(vrf))
print(" ip address {} 255.255.255.255".format(vpn1Loopback))
print("!")
print("router bgp {}".format(myAsn))
print(" address-family ipv4 vrf {}".format(vrf))
print("  bgp router-id {}".format(vpn1Loopback))
print("  redistribute connected")
print("  redistribute static")
print(" exit-address-family")
print("!")
print("")

print("! VPN2.SY4")
print("{}".format(vrfDefinition))
print("interface {}".format(loopbackInt))
print(" vrf forwarding {}".format(vrf))
print(" ip address {} 255.255.255.255".format(vpn2Loopback)) 
print("!")
print("router bgp {}".format(myAsn))
print(" address-family ipv4 vrf {}".format(vrf))
print("  bgp router-id {}".format(vpn2Loopback)) 
print("  redistribute connected")
print("  redistribute static")
print(" exit-address-family")
print("!")
print("")

print("! N1K-TA")
print("vlan {}".format(rd))
print(" name {}".format(vrf))
print("exit")
print("!")
print("port-profile type ethernet {}".format(n1kUplinkPortProfile))
print(" switchport trunk allowed vlan add {}".format(rd))
print("!")
print("{}".format(n1kPortProfileDefinition))
print("!")
print("")

