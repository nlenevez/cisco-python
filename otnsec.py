import sys,os,secrets
from ipaddress import IPv4Network

otnsecPolicy = (
        "otnsec policy OTNSECPOL\n"
        "otnsec policy OTNSECPOL cipher-suite AES-GCM-256\n"
        "otnsec policy OTNSECPOL sak-rekey-interval 604800\n"
        "\n"
        "ikev2 policy IKEV2POLICY\n"
        "ikev2 policy IKEV2POLICY proposal IKEV2PROPOSAL\n"
        )

otnsecKey = secrets.token_hex(32)

gccnet = IPv4Network(input("Please enter the GCC IP Network CIDR (eg. 192.168.0.0/30): "))
gcchosts = gccnet.hosts()
gccipA = next(gcchosts)
gccipB = next(gcchosts)
gccsubnet = gccnet.netmask
print("\n")

hostA = input("Please enter 'A' side COT hostname (eg. 33m-cot-1): ")
interfaceA = input("Please enter 'A' side interface ID (eg. 0/0/0/0): ")
interfaceAshort = format(interfaceA.replace('/',''))

hostB = input("Please enter 'B' side COT hostname (eg. 33m-cot-2): ")
interfaceB = input("Please enter 'B' side interface ID (eg. 0/0/0/0): ")
interfaceBshort = format(interfaceB.replace('/',''))

gccConfigA = (
        "controller ODU4{}/1 gcc2\n"
        "interface GCC{}/1 description gcc to {}\n"
        "interface GCC{}/1 ipv4 address {} {}\n"
        ).format(interfaceA, interfaceA, hostB, interfaceA, gccipA, gccsubnet)

gccConfigB = (
        "controller ODU4{}/1 gcc2\n"
        "interface GCC{}/1 description gcc to {}\n"
        "interface GCC{}/1 ipv4 address {} {}\n"
        ).format(interfaceB, interfaceB, hostA, interfaceB, gccipB, gccsubnet)

keyringA = (
        "keyring keyOTNSEC\n"
        "keyring keyOTNSEC peer {}-{}\n"
        "keyring keyOTNSEC peer {}-{} pre-shared-key clear {}\n"
        "keyring keyOTNSEC peer {}-{} address {} {}\n"
        ).format(hostB, interfaceBshort, hostB, interfaceBshort, otnsecKey, hostB, interfaceBshort, gccipB, gccsubnet)

keyringB = (
        "keyring keyOTNSEC\n"
        "keyring keyOTNSEC peer {}-{}\n"
        "keyring keyOTNSEC peer {}-{} pre-shared-key clear {}\n"
        "keyring keyOTNSEC peer {}-{} address {} {}\n"
        ).format(hostA, interfaceAshort, hostA, interfaceAshort, otnsecKey, hostA, interfaceAshort, gccipA, gccsubnet)

ikev2profileA = (
        "ikev2 profile IKEV2PROF_{}_{}\n"
        "ikev2 profile IKEv2PROF_{}_{} match identity remote address {} {}\n"
        "ikev2 profile IKEv2PROF_{}_{} keyring keyOTNSEC\n"
        "ikev2 profile IKEv2PROF_{}_{} lifetime 28800\n"
        ).format(hostB, interfaceBshort, hostB, interfaceBshort, gccipB, gccsubnet, hostB, interfaceBshort, hostB, interfaceBshort)

ikev2profileB = (
        "ikev2 profile IKEV2PROF_{}_{}\n"
        "ikev2 profile IKEv2PROF_{}_{} match identity remote address {} {}\n"
        "ikev2 profile IKEv2PROF_{}_{} keyring keyOTNSEC\n"
        "ikev2 profile IKEv2PROF_{}_{} lifetime 28800\n"
        ).format(hostA, interfaceAshort, hostA, interfaceAshort, gccipA, gccsubnet, hostA, interfaceAshort, hostA, interfaceAshort)

interfaceConfigA=""
for sessionId in range(1,5):
  interfaceConfigA += ("controller ODU4{}/{} otnsec policy OTNSECPOL\n").format(interfaceA, sessionId)
  interfaceConfigA += ("controller ODU4{}/{} otnsec ikev2 IKEV2PROF_{}_{}\n").format(interfaceA, sessionId, hostB, interfaceBshort)
  interfaceConfigA += ("controller ODU4{}/{} otnsec source ipv4 {}\n").format(interfaceA, sessionId, gccipA)
  interfaceConfigA += ("controller ODU4{}/{} otnsec destination ipv4 {}\n").format(interfaceA, sessionId, gccipB)
  interfaceConfigA += ("controller ODU4{}/{} otnsec session-id {}\n").format(interfaceA, sessionId, sessionId)

interfaceConfigB=""
for sessionId in range(1,5):
  interfaceConfigB += ("controller ODU4{}/{} otnsec policy OTNSECPOL\n").format(interfaceB, sessionId)
  interfaceConfigB += ("controller ODU4{}/{} otnsec ikev2 IKEV2PROF_{}_{}\n").format(interfaceB, sessionId, hostA, interfaceAshort)
  interfaceConfigB += ("controller ODU4{}/{} otnsec source ipv4 {}\n").format(interfaceB, sessionId, gccipB)
  interfaceConfigB += ("controller ODU4{}/{} otnsec destination ipv4 {}\n").format(interfaceB, sessionId, gccipA)
  interfaceConfigB += ("controller ODU4{}/{} otnsec session-id {}\n").format(interfaceB, sessionId, sessionId)

print("A Side Configuration - {}\n".format(hostA))
print("=======================================\n")
print(otnsecPolicy)
print(gccConfigA)
print(keyringA)
print(ikev2profileA)
print(interfaceConfigA)
print("\n")
print("B Side Configuration - {}\n".format(hostB))
print("=======================================\n")
print(otnsecPolicy)
print(gccConfigB)
print(keyringB)
print(ikev2profileB)
print(interfaceConfigB)
print("\n")
