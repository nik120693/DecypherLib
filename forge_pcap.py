import struct
import binascii

# Il tuo target generato con AES-256 KDF
hex_payload = "2e44676ea45aa8b04b39b14d1d1595c85782bc3eb80218acf30971862af1ff6719e5366b45999c250d2b59ccb2a92579097d6e962beb13ca951ba372a0d0c4a01185aa555824a22a29af1852cc0d912b"
payload_bytes = binascii.unhexlify(hex_payload)

# 1. PCAP Global Header (Indica che il file è un PCAP Ethernet standard)
# magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network(1=Ethernet)
global_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

# 2. Decapsulamento OSI Inverso (Costruiamo i frame)
eth_header = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00' # 14 byte (EtherType IPv4)
ip_header = b'\x45\x00' + struct.pack('>H', 20 + 20 + len(payload_bytes)) + b'\x00\x00\x40\x00\x40\x06\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01' # 20 byte (Protocollo TCP)
tcp_header = b'\x00\x50\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00\x00\x00\x00\x00\x00\x00' # 20 byte (Porta 80 -> 80)

packet_data = eth_header + ip_header + tcp_header + payload_bytes

# 3. PCAP Packet Header (Timestamp e lunghezza del singolo pacchetto)
packet_header = struct.pack('<IIII', 0, 0, len(packet_data), len(packet_data))

# 4. Scrittura Binaria su Disco
with open('capture.pcap', 'wb') as f:
    f.write(global_header)
    f.write(packet_header)
    f.write(packet_data)

print("[+] Falsificazione Rete Completata: 'capture.pcap' generato con successo.")