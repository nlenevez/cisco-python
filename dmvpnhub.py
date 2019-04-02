import sys
import getpass

client = input("Please enter the client name: ")
psk = getpass.getpass("Please enter the PSK (pre-shared-key): ")
nhrpKey = input("Please enter the NHRP Authentication Key: ")
if len(nhrpKey) > 7:
	sys.exit("NHRP key must be 7 characters or less")
primaryNhrp = input("Please enter the primary NHRP (Public) IP Address: ")
primaryNhrpMap = input("Please enter the primary NHRP (Private) IP Address: ")
backupNhrp = input("Please enter the backup NHRP (Public) IP Address: ")
backupNhrpMap = input("Please enter the backup NHRP (Private) IP Address: ")
networkId = input("Please enter the RD/Network ID: ")
tunnelMask = input("Please enter the Tunnel Subnet Mask: ")
tunnelCidr = input("Please enter the Tunnel CIDR range: ")

vrf = "IPN-{}".format(client)
peergroup = "IPN-{}-Spokes".format(client)
lowerClient = "{}".format(client.lower())
loopback = "Loopback{}001".format(networkId)
tunnelInterface = "Tunnel{}".format(networkId)

cryptoIkev2Policy = (
    "crypto ikev2 policy flexvpn-{}\n"
    " match address local {}\n"
    " proposal AES256-SHA256\n"
    "!"
).format(lowerClient,primaryNhrp)

cryptoIkev2Profile = (
    "crypto ikev2 profile flexvpn-{}\n"
    " match address local interface {}\n"
    " match identity remote any\n"
    " authentication local pre-share\n"
    " authentication remote pre-share\n"
    " keyring aaa flexvpn name-mangler RadiusRealm\n"
    " dpd 30 5 periodic\n"
    " aaa authorization group psk list flexvpn\n"
    " aaa authorization user psk cached\n"
    " aaa accounting psk flexvpn\n"
    "!"
).format(lowerClient,loopback)

cryptoIpsecProfile = (
    "crypto ipsec profile flexvpn-{}\n"
    " set transform-set ESP-AES-256-SHA\n"
    " set ikev2-profile flexvpn-{}\n"
    " set reverse-route tag 1\n"
    "!"
).format(lowerClient,lowerClient)

primaryLoopbackInterface = (
    "interface {}\n"
    " description {} DMVPN Termination\n"
    " ip address {} 255.255.255.255\n"
    "!"
).format(loopback,client,primaryNhrp)

backupLoopbackInterface = (
    "interface {}\n"
    " description {} DMVPN Termination\n"
    " ip address {} 255.255.255.255\n"
    "!"
).format(loopback,client,backupNhrp)

primaryDmvpnTunnel = (
    "interface {}\n"		# tunnelInterface
    " bandwidth 10000\n"
    " ip address {} {}\n"           # primaryNhrpMap, tunnelMask
    " no ip redirects\n"
    " ip mtu 1400\n"
    " ip nhrp authentication {}\n"    # nhrpKey
    " ip nhrp map multicast dynamic\n"
    " ip nhrp network-id {}\n"        # networkId
    " ip tcp adjust-mss 1360\n"
    " tunnel source {}\n"             # loopback
    " tunnel mode gre multipoint\n"
    " tunnel key {}\n"                # networkId
    " tunnel protection ipsec profile flexvpn-{}\n"   # lowerClient
    "!"
).format(tunnelInterface, primaryNhrpMap, tunnelMask, nhrpKey, networkId, loopback, networkId, lowerClient)

backupDmvpnTunnel = (
    "interface {}\n"		# tunnelInterface
    " bandwidth 10000\n"
    " ip address {} {}\n"           # backupNhrpMap, tunnelMask
    " no ip redirects\n"
    " ip mtu 1400\n"
    " ip nhrp authentication {}\n"    # nhrpKey
    " ip nhrp map multicast dynamic\n"
    " ip nhrp network-id {}\n"        # networkId
    " ip tcp adjust-mss 1360\n"
    " tunnel source {}\n"             # loopback
    " tunnel mode gre multipoint\n"
    " tunnel key {}\n"                # networkId
    " tunnel protection ipsec profile flexvpn-{}\n"   # lowerClient
    "!"
).format(tunnelInterface, backupNhrpMap, tunnelMask, nhrpKey, networkId, loopback, networkId, lowerClient)

primaryRoutingConfig = (
    "router bgp 38826\n"                 
    " bgp listen range {} peer-group {}\n"    # tunnelCidr, peergroup
    " !\n"
    " address-family ipv4 vrf {}\n"           # vrf
    " neighbor {} peer-group\n"		# peergroup
    " neighbor {} remote-as 65{}\n"     # peergroup,networkId
    " neighbor {} update-source {}\n"   # peergroup,tunnelInterface
    " neighbor {} next-hop-self all\n"  # peergroup
    " neighbor {} weight 2000\n"	# peergroup
    " exit-address-family\n"
    "!"
).format(tunnelCidr,peergroup,vrf,peergroup,peergroup,networkId,peergroup,tunnelInterface,peergroup,peergroup)

backupRoutingConfig = (
    "router bgp 38826\n"                 
    " bgp listen range {} peer-group {}\n"    # tunnelCidr, peergroup
    " !\n"
    " address-family ipv4 vrf {}\n"           # vrf
    " neighbor {} peer-group\n"		# peergroup
    " neighbor {} remote-as 65{}\n"     # peergroup,networkId
    " neighbor {} update-source {}\n"   # peergroup,tunnelInterface
    " neighbor {} next-hop-self all\n"  # peergroup
    " neighbor {} weight 1000\n"	# peergroup
    " neighbor {} route-map rm_Set_LocalPref_90 in\n"	# peergroup
    " exit-address-family\n"
    "!"
).format(tunnelCidr,peergroup,vrf,peergroup,peergroup,networkId,peergroup,tunnelInterface,peergroup,peergroup,peergroup)

print("! FlexVPN Primary Hub Configuration\n")
print("{}".format(cryptoIkev2Policy))
print("{}".format(cryptoIkev2Profile))
print("{}".format(cryptoIpsecProfile))
print("{}".format(primaryDmvpnTunnel))
print("{}".format(primaryRoutingConfig))
print("")
print("! FlexVPN Backup Hub Configuration\n")
print("{}".format(cryptoIkev2Policy))
print("{}".format(cryptoIkev2Profile))
print("{}".format(cryptoIpsecProfile))
print("{}".format(backupDmvpnTunnel))
print("{}".format(backupRoutingConfig))
print("")

