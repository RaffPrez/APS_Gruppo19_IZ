import json, base64, secrets
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEYS_DIR = Path("keys")
DATA_DIR = Path("data")
KEYS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

FIELD_PRIME = 2**257 - 93

def threshold_split(secret_bytes: bytes, t: int, n: int) -> list:
    # divide un segreto in n frammenti; ne servono almeno t per ricostruirlo (schema a soglia)
    padded = secret_bytes.ljust(32, b'\x00')
    secret_int = int.from_bytes(padded, 'big')                  # segreto -> numero intero
    assert secret_int < FIELD_PRIME, "Secret troppo grande per il campo"
    # polinomio casuale di grado t-1: il termine noto E' il segreto
    coeffs = [secret_int] + [secrets.randbelow(FIELD_PRIME) for _ in range(t - 1)]
    shares = []
    for x in range(1, n + 1):                                   # valuto il polinomio in x = 1..n
        y = sum(c * pow(x, i, FIELD_PRIME) for i, c in enumerate(coeffs)) % FIELD_PRIME
        shares.append((x, y))                                   # ogni frammento e' un punto (x, y)
    return shares

SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_LEN = 2**14, 8, 1, 32

def hash_password(password: str) -> dict:
    # trasforma la password in un hash salato con Scrypt (lento apposta, anti brute-force)
    salt = secrets.token_bytes(16)                              # sale casuale, diverso per ogni utente
    derived = Scrypt(salt=salt, length=SCRYPT_LEN,
                     n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password.encode())
    return {"salt": base64.b64encode(salt).decode(),            # su disco salvo solo sale + hash
            "pwd_hash": base64.b64encode(derived).decode()}

def _gen_rsa(key_size=2048):
    # coppia di chiavi RSA (2048 bit, esponente pubblico standard 65537)
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

def _priv_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

def _pub_pem(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

print("=== Setup Sistema E-Voting ===\n")
print("NOTA: la CA è considerata esistente ma NON è implementata nel codice.")
print("      Le chiavi pubbliche di IdP e AE vengono pubblicate direttamente.\n")

print("1. Generazione coppia di chiavi IdP (RSA 2048-bit)...")
idp_key = _gen_rsa(2048)
(KEYS_DIR / "idp_private.pem").write_bytes(_priv_pem(idp_key))
(KEYS_DIR / "idp_public.pem").write_bytes(_pub_pem(idp_key))

print("2. Generazione coppia di chiavi AE (RSA 2048-bit) con condivisione del segreto a soglia (t=3, n=5)...")
ae_key = _gen_rsa(2048)
(KEYS_DIR / "ae_public.pem").write_bytes(_pub_pem(ae_key))

# la chiave privata dell'AE NON va salvata in chiaro: la cifro con AES-256-GCM
aes_key = secrets.token_bytes(32)                               # chiave AES-256 casuale
ae_priv_der = ae_key.private_bytes(
    serialization.Encoding.DER,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
nonce = secrets.token_bytes(12)                                 # nonce di 96 bit (usato una sola volta)
ae_enc = AESGCM(aes_key).encrypt(nonce, ae_priv_der, None)      # cifra + tag di integrità
(KEYS_DIR / "ae_private_enc.json").write_text(json.dumps({
    "algorithm": "AES-256-GCM",
    "nonce": base64.b64encode(nonce).decode(),
    "ciphertext": base64.b64encode(ae_enc).decode(),
}, indent=2))

# divido la chiave AES in n=5 frammenti, soglia t=3: nessun commissario da solo apre l'urna
t, n = 3, 5
commissioners = ["Commissario Alfa", "Commissario Beta", "Commissario Gamma",
                 "Commissario Delta", "Commissario Epsilon"]
shares = threshold_split(aes_key, t, n)
threshold_data = {
    "t": t, "n": n,
    "shares": [
        {"commissioner": commissioners[i], "share_id": x, "share_value": hex(y)}
        for i, (x, y) in enumerate(shares)
    ]
}
(KEYS_DIR / "threshold_shares.json").write_text(json.dumps(threshold_data, indent=2))
print(f"   Frammenti distribuiti a {n} commissari, soglia minima: {t}")
for s in threshold_data["shares"]:
    print(f"   [{s['commissioner']}] share_id={s['share_id']}")

print("\n3. Creazione database elettori (10 cittadini di test)...")
voters = [
    {"voter_id": "VT001", "nome": "Mario Rossi",       "tessera": "AB1234567", "spid_id": "mrossi",    "password": "Referendum2026!"},
    {"voter_id": "VT002", "nome": "Laura Bianchi",      "tessera": "CD2345678", "spid_id": "lbianchi",  "password": "Referendum2026!"},
    {"voter_id": "VT003", "nome": "Giuseppe Verdi",     "tessera": "EF3456789", "spid_id": "gverdi",    "password": "Referendum2026!"},
    {"voter_id": "VT004", "nome": "Anna Ferrari",       "tessera": "GH4567890", "spid_id": "aferrari",  "password": "Referendum2026!"},
    {"voter_id": "VT005", "nome": "Luca Esposito",      "tessera": "IJ5678901", "spid_id": "lesposito", "password": "Referendum2026!"},
    {"voter_id": "VT006", "nome": "Giulia Romano",      "tessera": "KL6789012", "spid_id": "gromano",   "password": "Referendum2026!"},
    {"voter_id": "VT007", "nome": "Marco Ricci",        "tessera": "MN7890123", "spid_id": "mricci",    "password": "Referendum2026!"},
    {"voter_id": "VT008", "nome": "Francesca Marino",   "tessera": "OP8901234", "spid_id": "fmarino",   "password": "Referendum2026!"},
    {"voter_id": "VT009", "nome": "Roberto Conti",      "tessera": "QR9012345", "spid_id": "rconti",    "password": "Referendum2026!"},
    {"voter_id": "VT010", "nome": "Valentina Greco",    "tessera": "ST0123456", "spid_id": "vgreco",    "password": "Referendum2026!"},
]

# sostituisco la password in chiaro con il suo hash salato prima di salvare su disco
for v in voters:
    v.update(hash_password(v.pop("password")))
(DATA_DIR / "voters.json").write_text(json.dumps(voters, indent=2, ensure_ascii=False), encoding="utf-8")

print("4. Configurazione referendum...")
election_config = {
    "name": "Referendum Nazionale 2026",
    "question": "Sei favorevole all'approvazione della proposta di revisione costituzionale?",
    "options": ["SI", "NO", "BIANCA"],
    "option_labels": {"SI": "Sì", "NO": "No", "BIANCA": "Scheda Bianca"},
    "status": "open",
    "start_time": "2026-06-01T08:00:00",
    "end_time": "2026-06-30T22:00:00",
}
(DATA_DIR / "election_config.json").write_text(json.dumps(election_config, indent=2, ensure_ascii=False), encoding="utf-8")

print("5. Inizializzazione database...")
(DATA_DIR / "bulletin_board.json").write_text("[]")
(DATA_DIR / "used_hashes.json").write_text("[]")
(DATA_DIR / "results.json").write_text(json.dumps({"status": "not_computed", "counts": {}, "total_ballots": 0}, indent=2))

print("\n=== Setup completato ===")
print("\nCredenziali di test (password uguale per tutti: Referendum2026!)")
print(f"{'spid_id':<12} | {'nome':<20} | tessera")
print("-" * 48)
for v in voters:
    print(f"{v['spid_id']:<12} | {v['nome']:<20} | {v['tessera']}")
print("\nAvvia il server: python app.py")
