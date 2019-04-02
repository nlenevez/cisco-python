import sys
import getpass

vrf = input("Please enter the WAN VRF name: ")
username = input("Please enter the RADIUS username: ")
psk = getpass.getpass("Please enter the PSK (pre-shared-key): ")
nhrpKey = input("Please enter the NHRP Authentication Key: ")
primaryNhrp = input("Please enter the primary NHRP (Public) IP Address: ")
primaryNhrpMap = input("Please enter the primary NHRP (Private) IP Address: ")
backupNhrp = input("Please enter the backup NHRP (Public) IP Address: ")
backupNhrpMap = input("Please enter the backup NHRP (Private) IP Address: ")
networkId = input("Please enter the Network ID: ")
tunnelSource = input("Please enter the Tunnel WAN Interface: ")
tunnelIP = input("Please enter the Tunnel IP address: ")
tunnelMask = input("Please enter the Tunnel Subnet Mask: ")
bgpAsn = input("Please enter the BGP ASN: ")
lanCidr = input("Please enter the LAN range in CIDR notation: ")

vrfDefinition = (
    "vrf definition {}\n"
    " rd 1:1\n"
    " !\n"
    " address-family ipv4\n"
    " exit-address-family\n"
    "!"
).format(vrf)

cryptoBase = (
    "aaa authorization network flexvpn local\n"
    "crypto ikev2 authorization policy flexvpn\n"
    " route set interface\n"
    "!\n"
    "crypto ikev2 proposal AES256-SHA256\n"
    " encryption aes-cbc-256\n"
    " integrity sha256\n"
    " group 14\n"
    "!\n"
    "crypto ikev2 dpd 30 5 on-demand\n"
    "!"
)

cryptoKeyring = (
    "crypto ikev2 keyring Infinite\n"
    " peer Infinite\n"
    "  address 0.0.0.0 0.0.0.0\n"
    "  pre-shared-key {}\n"
    "!"
).format(psk)

cryptoIkev2Policy = (
    "crypto ikev2 policy flexvpn\n"
    " match fvrf {}\n"
    " proposal AES256-SHA256\n"
    "!"
).format(vrf)

cryptoIkev2Profile = (
    "crypto ikev2 profile flexvpn\n"
    " match fvrf {}\n"
    " identity local email {}\n"
    " match identity remote any\n"
    " authentication local pre-share\n"
    " authentication remote pre-share\n"
    " keyring local Infinite\n"
    " aaa authorization group psk list flexvpn flexvpn\n"
    "!"
).format(vrf,username)

cryptoTransform = (
    "crypto ipsec transform-set ESP-AES-256-SHA esp-aes 256 esp-sha-hmac\n"
    " mode transport\n"
    "!"
)

cryptoIpsecProfile = (
    "crypto ipsec profile flexvpn\n"
    " set transform-set ESP-AES-256-SHA\n"
    " set ikev2-profile flexvpn\n"
    "!"
)

dmvpnTunnel = (
    "interface Tunnel1\n"
    " ip address {} {}\n"           # TunnelIP, TunnelMask
    " no ip redirects\n"
    " ip mtu 1400\n"
    " ip nhrp authentication {}\n"  # nhrpKey
    " ip nhrp map {} {}\n"          # primaryNhrpMap, primaryNhrp
    " ip nhrp map multicast {}\n"   # primaryNhrp
    " ip nhrp map {} {}\n"          # backupNhrpMap, backupNhrp
    " ip nhrp map multicast {}\n"   # backupNhrp
    " ip nhrp network-id {}\n"      # networkId
    " ip nhrp nhs {} priority 1\n"  # primaryNhrpMap
    " ip nhrp nhs {} priority 2\n"  # backupNhrpMap
    " ip tcp adjust-mss 1360\n"
    " tunnel source {}\n"           # tunnelSource
    " tunnel mode gre multipoint\n"
    " tunnel key {}\n"              # networkID
    " tunnel vrf {}\n"              # vrf
    " tunnel protection ipsec profile flexvpn\n"
    "!"
).format(tunnelIP,tunnelMask,nhrpKey,primaryNhrpMap,primaryNhrp,primaryNhrp,backupNhrp,backupNhrpMap,backupNhrpMap,networkId,primaryNhrpMap,backupNhrpMap,tunnelSource,networkId,vrf)

routingConfig = (
    "router bgp {}\n"                 # bgpAsn
    " bgp log-neighbor-changes\n"
    " neighbor flexvpn-hubs peer-group\n"
    " neighbor flexvpn-hubs remote-as 38826\n"
    " neighbor {} peer-group flexvpn-hubs\n"  # primaryNhrpMap
    " neighbor {} peer-group flexvpn-hubs\n"  # backupNhrpMap
    " !\n"
    " address-family ipv4\n"
    "  redistribute connected\n"
    "  neighbor flexvpn-hubs allowas-in\n"
    "  neighbor flexvpn-hubs prefix-list pl_Announce-to-Infinite out\n"
    "  neighbor {} activate\n"              # primaryNhrpMap
    "  neighbor {} weight 2000\n"           # primaryNhrpMap
    "  neighbor {} activate\n"              # backupNhrpMap
    "  neighbor {} weight 1000\n"           # backupNhrpMap
    " exit-address-family\n"
    "!\n"
    "ip route vrf {} 0.0.0.0 0.0.0.0 {}\n"    # vrf, tunnelSource
    "ip prefix-list pl_Announce-to-Infinite seq 1000 permit {}\n"
    "!"
).format(bgpAsn,primaryNhrpMap,backupNhrpMap,primaryNhrpMap,primaryNhrpMap,backupNhrpMap,backupNhrpMap,vrf,tunnelSource,lanCidr)

print("! DMVPN Spoke Configuration\n")
print("{}".format(vrfDefinition))
print("{}".format(cryptoBase))
print("{}".format(cryptoKeyring))
print("{}".format(cryptoIkev2Policy))
print("{}".format(cryptoIkev2Profile))
print("{}".format(cryptoTransform))
print("{}".format(cryptoIpsecProfile))
print("{}".format(dmvpnTunnel))
print("{}".format(routingConfig))
print("")

