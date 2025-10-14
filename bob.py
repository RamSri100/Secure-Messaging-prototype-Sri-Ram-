# bob.py
import os, base64, json
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64(x): return base64.b64encode(x).decode()
def ub64(x): return base64.b64decode(x)

def save_pem(privkey, priv_path, pub_path):
    with open(priv_path, "wb") as f:
        f.write(privkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    pub = privkey.public_key()
    with open(pub_path, "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

def load_ed25519_private(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
def load_ed25519_public(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

# ensure bob identity key
if not os.path.exists("ed25519_bob_private.pem"):
    sk = ed25519.Ed25519PrivateKey.generate()
    save_pem(sk, "ed25519_bob_private.pem", "ed25519_bob_public.pem")
    print("Generated Bob identity keypair.")
sk = load_ed25519_private("ed25519_bob_private.pem")

# optionally load Alice's public key file (put it here)
if not os.path.exists("ed25519_alice_public.pem"):
    print("Please put Alice's public key PEM in ed25519_alice_public.pem then press Enter.")
    input()
pk_alice = load_ed25519_public("ed25519_alice_public.pem")

# Wait for message 1 from Alice
print("\nPaste Alice's JSON (message 1):")
msg1_json = input().strip()
msg1 = json.loads(msg1_json)
A_pub = ub64(msg1["eph_pub_b64"])
sig_a = ub64(msg1["sig_b64"])
# verify
try:
    pk_alice.verify(sig_a, A_pub)
    print("Alice signature on ephemeral pub verified.")
except Exception as e:
    print("Signature verify failed:", e); raise SystemExit(1)

# Now Bob creates ephemeral, signs and responds
b_eph = x25519.X25519PrivateKey.generate()
B_pub = b_eph.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
sig_b = sk.sign(B_pub)
resp = {
    "identity":"bob",
    "identity_pub_pem": open("ed25519_bob_public.pem","rb").read().decode(),
    "eph_pub_b64": b64(B_pub),
    "sig_b64": b64(sig_b)
}
print("\n=== MESSAGE 2 (send to Alice) ===")
print(json.dumps(resp))
print("\nCopy that JSON and give to Alice.\n")

# compute shared secret
shared = b_eph.exchange(x25519.X25519PublicKey.from_public_bytes(A_pub))
hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data")
K = hkdf.derive(shared)
print("Derived session key K (hex):", K.hex())

aesgcm = AESGCM(K)
seq = 0
last_seen_seq = -1

def send_msg(plaintext: bytes):
    global seq
    nonce = os.urandom(12)
    aad = f"bob|{seq}".encode()
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    payload = {
        "from":"bob",
        "seq": seq,
        "nonce_b64": b64(nonce),
        "aad_b64": b64(aad),
        "ct_b64": b64(ct)
    }
    seq += 1
    print("\n=== OUTGOING MESSAGE ===")
    print(json.dumps(payload))
    print("\nCopy-paste that to Alice.\n")

def receive_msg(json_in):
    global last_seen_seq
    p = json.loads(json_in)
    seqr = p["seq"]
    if seqr <= last_seen_seq:
        print("Replay or old message detected. Rejecting.")
        return
    nonce = ub64(p["nonce_b64"])
    aad = ub64(p["aad_b64"])
    ct = ub64(p["ct_b64"])
    try:
        pt = aesgcm.decrypt(nonce, ct, aad)
    except Exception as e:
        print("Decryption/auth failed:", e); return
    last_seen_seq = seqr
    print(f"\nRECEIVED from {p['from']} seq={seqr}:")
    print(pt.decode())

print("\nEnter 's' to send, 'r' to paste received JSON, 'q' to quit.")
while True:
    cmd = input("cmd: ").strip().lower()
    if cmd == "s":
        txt = input("Message to send: ").encode()
        send_msg(txt)
    elif cmd == "r":
        blob = input("Paste received JSON message: ").strip()
        receive_msg(blob)
    elif cmd == "q":
        break
    else:
        print("unknown cmd")
