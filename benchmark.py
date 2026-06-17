import json, base64, hashlib, time, statistics
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, load_der_private_key
)

PSS  = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
FIELD_PRIME = 2**257 - 93

def bench(fn, iters):

    for _ in range(min(5, iters)):
        fn()
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return statistics.mean(samples)

def threshold_reconstruct(shares, t):
    prime = FIELD_PRIME
    pts = [(int(s["x"]), int(s["y"], 16)) for s in shares[:t]]
    result = 0
    for i, (xi, yi) in enumerate(pts):
        num, den = yi, 1
        for j, (xj, _) in enumerate(pts):
            if i != j:
                num = (num * (prime - xj)) % prime
                den = (den * ((xi - xj) % prime)) % prime
        result = (result + num * pow(den, prime - 2, prime)) % prime
    return result.to_bytes(32, "big")

kd = Path("keys")
idp_priv = load_pem_private_key((kd / "idp_private.pem").read_bytes(), password=None)
ae_pub   = load_pem_public_key((kd / "ae_public.pem").read_bytes())

thr = json.loads((kd / "threshold_shares.json").read_text())
shares = [{"x": s["share_id"], "y": s["share_value"]} for s in thr["shares"][:thr["t"]]]
aes_key = threshold_reconstruct(shares, thr["t"])
enc = json.loads((kd / "ae_private_enc.json").read_text())
ae_priv_der = AESGCM(aes_key).decrypt(base64.b64decode(enc["nonce"]), base64.b64decode(enc["ciphertext"]), None)
ae_priv = load_der_private_key(ae_priv_der, password=None)

tessera = "AB1234567"
tessera_hash = hashlib.sha256(tessera.encode()).hexdigest()
eph = rsa.generate_private_key(public_exponent=65537, key_size=2048)
eph_spki = base64.b64encode(eph.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

token_payload = {
    "eph_pubkey_spki": eph_spki, "exp": 9999999999, "iat": 1111111111,
    "iss": "mock-idp.referendum.gov.it", "tessera_hash": tessera_hash,
}
token_string = json.dumps(token_payload, separators=(",", ":"), sort_keys=True)
token_sig = idp_priv.sign(token_string.encode(), PSS, hashes.SHA256())
token_sig_b64 = base64.b64encode(token_sig).decode()

ct = ae_pub.encrypt(b"SI", OAEP)
ct_b64 = base64.b64encode(ct).decode()
tc = hashlib.sha256(ct).hexdigest()
ballot_input = (ct_b64 + "|" + token_string + "|" + token_sig_b64).encode()
ballot_sig = eph.sign(ballot_input, PSS, hashes.SHA256())
ballot_sig_b64 = base64.b64encode(ballot_sig).decode()
ballot_payload = json.dumps({
    "ciphertext": ct_b64, "tracking_code": tc, "token_string": token_string,
    "token_sig": token_sig_b64, "ballot_sig": ballot_sig_b64,
})

nonce = base64.b64decode(enc["nonce"]); ct_aes = base64.b64decode(enc["ciphertext"])

print("=" * 64)
print("  PRESTAZIONI — operazioni crittografiche (tempo medio)")
print("=" * 64)
rows = [
    ("Keygen effimera RSA-2048 (Wallet)",
     bench(lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048), 25)),
    ("SHA-256 (hash tessera / tracking code)",
     bench(lambda: hashlib.sha256(ct).hexdigest(), 200000)),
    ("RSA-OAEP encrypt voto (Wallet, pk_AE)",
     bench(lambda: ae_pub.encrypt(b"SI", OAEP), 2000)),
    ("RSA-PSS sign token (IdP, sk_IdP)",
     bench(lambda: idp_priv.sign(token_string.encode(), PSS, hashes.SHA256()), 2000)),
    ("RSA-PSS sign scheda (Wallet, sk_voter)",
     bench(lambda: eph.sign(ballot_input, PSS, hashes.SHA256()), 2000)),
    ("RSA-PSS verify firma (AE)",
     bench(lambda: idp_priv.public_key().verify(token_sig, token_string.encode(), PSS, hashes.SHA256()), 5000)),
    ("Ricostruzione segreto a soglia (t=3)",
     bench(lambda: threshold_reconstruct(shares, thr["t"]), 20000)),
    ("AES-256-GCM decrypt chiave sk_AE",
     bench(lambda: AESGCM(aes_key).decrypt(nonce, ct_aes, None), 20000)),
    ("RSA-OAEP decrypt scheda (AE, sk_AE)",
     bench(lambda: ae_priv.decrypt(ct, OAEP), 2000)),
]
for name, ms in rows:
    print(f"  {name:<44} {ms:8.4f} ms")

print("\n" + "=" * 64)
print("  DIMENSIONI MESSAGGI")
print("=" * 64)
sizes = [
    ("Crittogramma C (raw)",            len(ct)),
    ("Crittogramma C (base64)",         len(ct_b64)),
    ("Firma RSA-PSS (raw)",             len(token_sig)),
    ("Firma RSA-PSS (base64)",          len(token_sig_b64)),
    ("Token JSON T (string)",           len(token_string)),
    ("Tracking code (hex)",             len(tc)),
    ("Chiave pubblica effimera (b64 SPKI)", len(eph_spki)),
    ("Payload scheda completo (JSON)",  len(ballot_payload)),
]
for name, n in sizes:
    extra = f"  (~{n/1024:.2f} KB)" if n > 1024 else ""
    print(f"  {name:<44} {n:6d} byte{extra}")

print("\n[OK] Benchmark completato.")
