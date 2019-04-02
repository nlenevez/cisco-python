import sys

asn = input("Please enter the ASN: ")
desc = input("Please enter the peer description: ")
ipv4 = input("Please enter the IPv4 neighbor (blank for none): ")
ipv6 = input("Please enter the IPv6 neighbor (blank for none): ")

print("router bgp 38826")

if len(ipv4) > 1:
	print(" neighbor {} remote-as {}".format(ipv4,asn))
	print(" neighbor {} description --- {} ---".format(ipv4,desc))
	print(" neighbor {} shutdown".format(ipv4))
if len(ipv6) > 1:
        print(" neighbor {} remote-as {}".format(ipv6,asn))
        print(" neighbor {} description --- {} ---".format(ipv6,desc))
        print(" neighbor {} shutdown".format(ipv6))

print("!")

if len(ipv4) > 1:
	print(" address-family ipv4")
	print("  neighbor {} activate".format(ipv4))
	print("  neighbor {} inherit peer-policy PEERING-BLPA-v4".format(ipv4))
	print(" !")

if len(ipv6) > 1:
        print(" address-family ipv6 unicast")
        print("  neighbor {} activate".format(ipv6))
        print("  neighbor {} inherit peer-policy PEERING-BLPA-v6".format(ipv6))
        print(" !")

if len(ipv4) > 1:
        print(" no neighbor {} shutdown".format(ipv4))

if len(ipv6) > 1:
        print(" no neighbor {} shutdown".format(ipv6))

print("!")
print("")

