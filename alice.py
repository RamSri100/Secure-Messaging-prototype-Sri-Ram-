# alice.py
import os, base64, json
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- helpers ----------
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

def b64(x): return base64.b64encode(x).decode()
def ub64(x): return base64.b64decode(x)

# ---------- ensure long-term identity key ----------
if not os.path.exists("ed25519_alice_private.pem"):
    sk = ed25519.Ed25519PrivateKey.generate()
    save_pem(sk, "ed25519_alice_private.pem", "ed25519_alice_public.pem")
    print("Generated Alice identity keypair. Public saved to ed25519_alice_public.pem")
sk = load_ed25519_private("ed25519_alice_private.pem")
pk_alice = sk.public_key()

# ---------- load Bob's public key (simulate pre-known) ----------
if not os.path.exists("ed25519_bob_public.pem"):
    print("Please put Bob's public key PEM in file ed25519_bob_public.pem (copy from Bob).")
    input("Press Enter when ready...")
pk_bob = load_ed25519_public("ed25519_bob_public.pem")

# ---------- Alice creates ephemeral X25519 and signs it ----------
a_eph = x25519.X25519PrivateKey.generate()
A_pub = a_eph.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
sig = sk.sign(A_pub)

msg1 = {
    "identity": "alice",
    "identity_pub_pem": open("ed25519_alice_public.pem","rb").read().decode(),
    "eph_pub_b64": b64(A_pub),
    "sig_b64": b64(sig)
}
print("\n=== MESSAGE 1 (send to Bob) ===")
print(json.dumps(msg1))
print("\nCopy the JSON above to Bob and wait for his response.\n")

# ---------- Wait for Bob's response (paste JSON) ----------
resp_json = input("Paste Bob's JSON response here: ").strip()
resp = json.loads(resp_json)
# verify Bob's signature on his ephemeral pub
B_pub = ub64(resp["eph_pub_b64"])
sig_b = ub64(resp["sig_b64"])
# parse Bob identity pub if provided, otherwise use pre-known
if "identity_pub_pem" in resp:
    # optionally persist
    open("ed25519_bob_public.pem","wb").write(resp["identity_pub_pem"].encode())
    pk_bob = load_ed25519_public("ed25519_bob_public.pem")

# verify signature
try:
    pk_bob.verify(sig_b, B_pub)
    print("Bob's signature on ephemeral pubkey verified.")
except Exception as e:
    print("Signature verification failed:", e)
    raise SystemExit(1)

# ---------- compute shared secret and derive session key ----------
shared = a_eph.exchange(x25519.X25519PublicKey.from_public_bytes(B_pub))
# derive 32-byte AES key via HKDF-SHA256
hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data")
K = hkdf.derive(shared)
print("Derived session key K (hex):", K.hex())

# ---------- Messaging loop (use AES-GCM) ----------
aesgcm = AESGCM(K)
seq = 0
last_seen_seq = -1

def send_msg(plaintext: bytes):
    global seq
    nonce = os.urandom(12)
    aad = f"alice|{seq}".encode()
    ct = aesgcm.encrypt(nonce, plaintext, aad)  # returns ciphertext||tag
    payload = {
        "from":"alice",
        "seq": seq,
        "nonce_b64": b64(nonce),
        "aad_b64": b64(aad),
        "ct_b64": b64(ct)
    }
    seq += 1
    print("\n=== OUTGOING MESSAGE ===")
    print(json.dumps(payload))
    print("\nCopy-paste that to Bob.\n")

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

# quick interactive loop
print("\nEnter 's' to send a message, 'r' to paste a received JSON blob, 'q' to quit.")
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
