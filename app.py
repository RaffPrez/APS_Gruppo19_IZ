import json, hashlib, base64, secrets, time
from pathlib import Path
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, load_der_public_key, load_der_private_key
)
from cryptography.exceptions import InvalidSignature, InvalidKey

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

import datetime as _dt
@app.template_filter("strftime")
def _strftime(ts):
    try:
        return _dt.datetime.fromtimestamp(int(ts)).strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return str(ts)

FIELD_PRIME = 2**257 - 93

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1

def _load_keys():
    # la CA non e' implementata: le chiavi pubbliche di IdP/AE sono ritenute autentiche per ipotesi
    kd = Path("keys")
    idp_priv = load_pem_private_key((kd / "idp_private.pem").read_bytes(), password=None)
    ae_pub   = load_pem_public_key((kd / "ae_public.pem").read_bytes())
    return {
        "idp_private": idp_priv,
        "idp_public":  idp_priv.public_key(),
        "ae_public":   ae_pub,
    }

try:
    KEYS = _load_keys()
except Exception as e:
    KEYS = {}
    print(f"[WARN] Chiavi non caricate: {e}\n       Esegui prima: python3 setup_keys.py")

def load_json(path: str) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def save_json(path: str, data: object):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def verify_password(password: str, voter: dict) -> bool:
    # verifica la password ricalcolando l'hash Scrypt col sale salvato (confronto a tempo costante)
    try:
        salt     = base64.b64decode(voter["salt"])
        expected = base64.b64decode(voter["pwd_hash"])
        Scrypt(salt=salt, length=len(expected),
               n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).verify(password.encode(), expected)
        return True
    except (InvalidKey, KeyError):
        return False

def ae_pubkey_spki_b64() -> str:
    spki = KEYS["ae_public"].public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(spki).decode()

def _scrutiny_done() -> bool:
    # True solo a scrutinio concluso: finche' e' False, urna pubblica e verifica restano chiuse
    try:
        return load_json("data/results.json").get("status") == "computed"
    except Exception:
        return False

def _threshold_reconstruct(shares: list, t: int) -> bytes:
    # rimette insieme la chiave segreta combinando t frammenti dei commissari (schema a soglia)
    prime = FIELD_PRIME
    pts   = [(int(s["x"]), int(s["y"], 16)) for s in shares[:t]]   # i t frammenti (x, y)
    result = 0
    for i, (xi, yi) in enumerate(pts):
        num, den = yi, 1
        for j, (xj, _) in enumerate(pts):
            if i != j:
                num = (num * (prime - xj)) % prime
                den = (den * ((xi - xj) % prime)) % prime
        # divisione mod p = moltiplicazione per l'inverso (pow(den, p-2, p))
        result = (result + num * pow(den, prime - 2, prime)) % prime
    return result.to_bytes(32, "big")                              # i 32 byte = chiave AES

@app.route("/")
def index():
    cfg = load_json("data/election_config.json")
    return render_template("index.html", election=cfg, scrutiny_done=_scrutiny_done())

@app.route("/bulletin-board")
def bulletin_board():
    # consultabile solo a scrutinio concluso
    if not _scrutiny_done():
        return render_template("bulletin_board.html", locked=True)
    bb      = load_json("data/bulletin_board.json")
    results = load_json("data/results.json")
    return render_template("bulletin_board.html", blocks=bb, results=results, locked=False)

@app.route("/verify")
def verify_page():
    # la verifica del proprio voto e' disponibile solo a scrutinio concluso
    return render_template("verify.html", locked=not _scrutiny_done())

@app.route("/verify/check")
def verify_check():
    if not _scrutiny_done():
        return jsonify({"found": False, "locked": True,
                        "error": "La verifica individuale sarà disponibile al termine dello scrutinio."}), 403
    tc = request.args.get("code", "").strip().lower()
    if not tc:
        return jsonify({"found": False, "error": "Codice non fornito"}), 400
    for block in load_json("data/bulletin_board.json"):
        if block["tracking_code"].lower() == tc:
            return jsonify({
                "found": True,
                "block_index": block["block_index"],
                "timestamp": block["timestamp"],
                "block_hash": block["block_hash"],
                "prev_hash":  block["prev_hash"],
            })
    return jsonify({"found": False})

@app.route("/auth/login")
def auth_login():
    method = request.args.get("method", "spid")
    return render_template("spid_login.html", method=method)

@app.route("/auth/authenticate", methods=["POST"])
def authenticate():
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type non valido"}), 400

    d        = request.json
    spid_id  = d.get("spid_id", "").strip()
    password = d.get("password", "").strip()

    voters = load_json("data/voters.json")
    voter  = next((v for v in voters if v["spid_id"] == spid_id), None)

    if not voter:
        return jsonify({"success": False, "error": "Identità SPID non trovata"}), 401
    # verifica la password (hash Scrypt salato)
    if not verify_password(password, voter):
        return jsonify({"success": False, "error": "Password non corretta"}), 401

    session.clear()                              # parto da una sessione pulita
    session["voter_id"]        = voter["voter_id"]
    session["idp_identity_ok"] = True
    session["idp_auth_time"]   = int(time.time())

    return jsonify({"success": True, "redirect": url_for("tessera_page")})

@app.route("/auth/tessera")
def tessera_page():
    if not session.get("idp_identity_ok"):
        return redirect(url_for("index"))
    voters = load_json("data/voters.json")
    voter  = next((v for v in voters if v["voter_id"] == session.get("voter_id")), None)
    nome   = voter["nome"] if voter else ""
    method = request.args.get("method", "spid")
    return render_template("tessera.html", nome=nome, method=method)

@app.route("/auth/verify-tessera", methods=["POST"])
def verify_tessera():
    if not session.get("idp_identity_ok"):
        return jsonify({"success": False, "error": "Sessione non valida — ripeti l'autenticazione"}), 401
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type non valido"}), 400

    tessera = (request.json or {}).get("tessera", "").strip()
    voters  = load_json("data/voters.json")
    voter   = next((v for v in voters if v["voter_id"] == session.get("voter_id")), None)

    if not voter:
        return jsonify({"success": False, "error": "Identità non trovata"}), 401
    # l'IdP controlla SOLO che la tessera corrisponda all'identita' (non i voti gia' espressi)
    if voter["tessera"] != tessera:
        return jsonify({"success": False, "error": "Tessera elettorale non corrispondente all'identità autenticata"}), 401

    session["tessera"]           = voter["tessera"]
    session["idp_authenticated"] = True
    session["idp_auth_time"]     = int(time.time())

    return jsonify({"success": True, "redirect": url_for("vote_page")})

@app.route("/idp/issue-token", methods=["POST"])
def issue_token():
    if not session.get("idp_authenticated"):
        return jsonify({"error": "Non autenticato con IdP"}), 401
    if not KEYS:
        return jsonify({"error": "Server non configurato — eseguire setup_keys.py"}), 500

    d             = request.json or {}
    tessera_hash  = d.get("tessera_hash", "").strip()
    eph_pubkey_spki = d.get("eph_pubkey_spki", "").strip()

    if not tessera_hash or not eph_pubkey_spki:
        return jsonify({"error": "Parametri mancanti"}), 400

    tessera = session["tessera"]

    # controllo che l'impronta inviata corrisponda alla tessera della sessione
    expected = hashlib.sha256(tessera.encode()).hexdigest()
    if expected != tessera_hash:
        return jsonify({"error": "Hash tessera non corrispondente all'identità autenticata"}), 400

    now = int(time.time())
    # contenuto del token: chiave usa-e-getta del votante, scadenza (1h), ora, emittente,
    # impronta della tessera. NB: nessun dato anagrafico (niente nome/voter_id)
    token_payload = {
        "eph_pubkey_spki": eph_pubkey_spki,
        "exp":             now + 3600,
        "iat":             now,
        "iss":             "mock-idp.referendum.gov.it",
        "tessera_hash":    tessera_hash,
    }
    # testo canonico (chiavi ordinate): la firma sara' verificabile in modo identico dal server
    token_string = json.dumps(token_payload, separators=(",", ":"), sort_keys=True)

    # l'IdP firma il token con la sua chiave privata (RSA-PSS): chi ha la pubblica puo' verificarlo
    sig = KEYS["idp_private"].sign(
        token_string.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )

    session.clear()                              # chiudo il dominio IdP: non potra' collegare l'utente al voto

    return jsonify({
        "token_string":  token_string,
        "token_sig":     base64.b64encode(sig).decode(),
        "ae_pubkey_oaep": ae_pubkey_spki_b64(),
    })

@app.route("/vote")
def vote_page():
    if not session.get("idp_authenticated"):
        return redirect(url_for("index"))
    cfg     = load_json("data/election_config.json")
    tessera = session.get("tessera", "")
    return render_template("vote.html", election=cfg, tessera=tessera)

@app.route("/ae/submit-ballot", methods=["POST"])
def submit_ballot():
    if not KEYS:
        return jsonify({"error": "Server non configurato"}), 500

    d = request.json or {}
    required = ["ciphertext", "tracking_code", "token_string", "token_sig", "ballot_sig"]
    if not all(k in d for k in required):
        return jsonify({"error": "Payload incompleto"}), 400

    ct_b64       = d["ciphertext"]
    tracking_code = d["tracking_code"]
    token_string  = d["token_string"]
    token_sig_b64 = d["token_sig"]
    ballot_sig_b64 = d["ballot_sig"]

    try:
        token = json.loads(token_string)
    except json.JSONDecodeError:
        return jsonify({"error": "Token JSON malformato"}), 400

    # 1) il token e' scaduto?
    if int(time.time()) > token.get("exp", 0):
        return jsonify({"error": "Token scaduto — riavvia la procedura di autenticazione"}), 401

    # 2) la firma dell'IdP sul token e' valida? (autenticita' dell'autorizzazione)
    try:
        KEYS["idp_public"].verify(
            base64.b64decode(token_sig_b64),
            token_string.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except (InvalidSignature, Exception):
        return jsonify({"error": "Firma IdP sul token non valida — scheda rifiutata"}), 401

    # 3) estraggo la chiave pubblica del votante dal token
    try:
        eph_pubkey = load_der_public_key(base64.b64decode(token["eph_pubkey_spki"]))
    except Exception:
        return jsonify({"error": "Chiave effimera nel token non valida"}), 400

    # 4) la firma del votante sulla scheda e' valida? (prova che la manda chi ha ricevuto il token)
    try:
        ballot_bytes = (ct_b64 + "|" + token_string + "|" + token_sig_b64).encode()
        eph_pubkey.verify(
            base64.b64decode(ballot_sig_b64),
            ballot_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except (InvalidSignature, Exception):
        return jsonify({"error": "Firma effimera sulla scheda non valida"}), 401

    # 5) la tessera ha gia' votato? (anti-doppio-voto, UNICO punto di controllo unicita')
    tessera_hash = token["tessera_hash"]
    used = load_json("data/used_hashes.json")
    if tessera_hash in used:
        return jsonify({"error": "Doppio voto rilevato — tessera già registrata nell'urna"}), 409

    # 6) il tracking code corrisponde al voto cifrato? (T deve essere SHA-256 del crittogramma)
    expected_tc = hashlib.sha256(base64.b64decode(ct_b64)).hexdigest()
    if tracking_code != expected_tc:
        return jsonify({"error": "Tracking code non corrispondente al crittogramma"}), 400

    # registrazione nella catena di hash (Bulletin Board)
    bb        = load_json("data/bulletin_board.json")
    prev_hash = bb[-1]["block_hash"] if bb else "0" * 64           # hash del blocco precedente (o 64 zeri)
    block     = {
        "block_index":   len(bb),
        "ciphertext":    ct_b64,
        "prev_hash":     prev_hash,
        "timestamp":     int(time.time()),
        "tracking_code": tracking_code,
    }
    # l'hash del blocco include prev_hash: lega ogni blocco al precedente (anti-manomissione)
    block_hash_input = json.dumps(block, separators=(",", ":"), sort_keys=True).encode()
    block["block_hash"] = hashlib.sha256(block_hash_input).hexdigest()

    bb.append(block)
    save_json("data/bulletin_board.json", bb)

    used.append(tessera_hash)                                      # segno la tessera come usata
    save_json("data/used_hashes.json", used)

    return jsonify({
        "success":       True,
        "tracking_code": tracking_code,
        "block_index":   block["block_index"],
        "block_hash":    block["block_hash"],
    })

@app.route("/bulletin-board/verify-chain")
def verify_chain():
    if not _scrutiny_done():
        return jsonify({"valid": False, "locked": True,
                        "error": "La Bulletin Board sarà consultabile al termine dello scrutinio."}), 403
    bb = load_json("data/bulletin_board.json")
    if not bb:
        return jsonify({"valid": True, "blocks": 0})
    # ricalcolo l'hash di ogni blocco e controllo che la catena non sia stata manomessa
    prev = "0" * 64
    for block in bb:
        stored_hash = block.get("block_hash")
        block_for_hash = {k: v for k, v in block.items() if k != "block_hash"}
        computed = hashlib.sha256(
            json.dumps(block_for_hash, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        if computed != stored_hash or block["prev_hash"] != prev:  # hash diverso o link rotto?
            return jsonify({"valid": False, "corrupted_at": block["block_index"]})
        prev = stored_hash
    return jsonify({"valid": True, "blocks": len(bb)})

@app.route("/pki/ae-pubkey")
def ae_pubkey_endpoint():
    if not KEYS:
        return jsonify({"error": "Keys not loaded"}), 500
    pem = KEYS["ae_public"].public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({
        "ae_public_key_pem":  pem.decode(),
        "ae_pubkey_spki_b64": ae_pubkey_spki_b64(),
    })

@app.route("/pki/idp-pubkey")
def idp_pubkey_endpoint():
    if not KEYS:
        return jsonify({"error": "Keys not loaded"}), 500
    pem = KEYS["idp_public"].public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({"idp_public_key_pem": pem.decode()})

@app.route("/admin")
def admin_page():
    threshold = load_json("keys/threshold_shares.json")
    bb      = load_json("data/bulletin_board.json")
    results = load_json("data/results.json")
    return render_template("admin.html", threshold=threshold, ballot_count=len(bb), results=results)

@app.route("/admin/decrypt", methods=["POST"])
def admin_decrypt():
    if not KEYS:
        return jsonify({"error": "Server non configurato"}), 500

    d      = request.json or {}
    shares = d.get("shares", [])
    threshold = load_json("keys/threshold_shares.json")
    t      = threshold["t"]

    if len(shares) < t:
        return jsonify({"error": f"Necessari almeno {t} frammenti (forniti: {len(shares)})"}), 400

    # ricostruisco la chiave AES dai frammenti dei commissari (servono almeno t)
    try:
        aes_key = _threshold_reconstruct(shares, t)
    except Exception as e:
        return jsonify({"error": f"Errore nella ricostruzione del segreto a soglia: {e}"}), 400

    # con la chiave AES riapro (AES-256-GCM) la chiave privata dell'AE
    try:
        enc = load_json("keys/ae_private_enc.json")
        ae_priv_der = AESGCM(aes_key).decrypt(
            base64.b64decode(enc["nonce"]),
            base64.b64decode(enc["ciphertext"]),
            None
        )
        ae_private_key = load_der_private_key(ae_priv_der, password=None)
    except Exception:
        return jsonify({"error": "Frammenti errati — impossibile ricostruire la chiave AE"}), 400

    bb, votes, errors = load_json("data/bulletin_board.json"), [], []
    if not bb:
        return jsonify({"error": "L'urna è vuota"}), 400

    # decifro ogni scheda con RSA-OAEP per ottenere il voto in chiaro
    for block in bb:
        try:
            pt = ae_private_key.decrypt(
                base64.b64decode(block["ciphertext"]),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )
            votes.append(pt.decode())
        except Exception as e:
            errors.append(f"Block {block['block_index']}: {e}")

    # mescolo i voti in ordine casuale (generatore sicuro) per scollegarli dall'ordine di arrivo
    for i in range(len(votes) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        votes[i], votes[j] = votes[j], votes[i]

    counts   = {k: 0 for k in ["SI", "NO", "BIANCA"]}
    for v in votes:
        counts[v] = counts.get(v, 0) + 1
    total = len(votes)

    results = {
        "status":          "computed",
        "total_ballots":   total,
        "counts":          counts,
        "percentages":     {k: round(v / total * 100, 2) if total else 0 for k, v in counts.items()},
        "shuffled_votes":  votes,
        "timestamp":       int(time.time()),
        "errors":          errors,
    }
    save_json("data/results.json", results)
    return jsonify({"success": True, "results": results})

@app.route("/admin/reset", methods=["POST"])
def admin_reset():
    save_json("data/bulletin_board.json", [])
    save_json("data/used_hashes.json", [])
    save_json("data/results.json", {"status": "not_computed", "counts": {}, "total_ballots": 0})
    return jsonify({"success": True, "message": "Urna azzerata"})

if __name__ == "__main__":
    print("Avvio E-Voting Server su http://localhost:5001")
    app.run(debug=True, port=5001, host="127.0.0.1")
