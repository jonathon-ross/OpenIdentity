#!/usr/bin/env python3
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[1]
v=json.loads((ROOT/"test-vectors/external-ad-binding-v1-crypto-pre-freeze.json").read_text())["referenceVectors"][0]
ldap=bytes.fromhex(v["objectGuidLdapOctetsHex"])
# Windows GUID textual fields interpret Data1/Data2/Data3 little-endian.
text=f"{int.from_bytes(ldap[0:4],'little'):08x}-{int.from_bytes(ldap[4:6],'little'):04x}-{int.from_bytes(ldap[6:8],'little'):04x}-{ldap[8:10].hex()}-{ldap[10:16].hex()}"
# RFC/UUID network-order bytes parsed naively from that displayed text.
runtime=bytes.fromhex(text.replace("-",""))
assert ldap.hex()=="00112233445566778899aabbccddeeff"
assert text=="33221100-5544-7766-8899-aabbccddeeff"
assert runtime.hex()=="33221100554477668899aabbccddeeff"
assert runtime!=ldap
print("AD objectGUID LDAP octets:",ldap.hex())
print("Displayed GUID text:",text)
print("Naive UUID/network bytes:",runtime.hex())
print("AD OBJECTGUID BYTE-ORDER TRAP VERIFIED")
