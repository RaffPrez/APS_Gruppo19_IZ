import json, base64, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key

import app
app.app.testing = True

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

ok = 0; fail = 0
def check(name, cond):
    global ok, fail
    print(("  [OK] " if cond else "  [FAIL] ") + name)
    if cond: ok += 1
    else: fail += 1

def client_vote(c, spid_id, password, tessera, choice):
    s = c

    r = s.post("/auth/authenticate", json={"spid_id": spid_id, "password": password})
    assert r.status_code == 200, ("auth", r.get_json())

    r = s.post("/auth/verify-tessera", json={"tessera": tessera})
    assert r.status_code == 200, ("verify-tessera", r.get_json())

    eph = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    eph_spki = base64.b64encode(eph.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    tessera_hash = hashlib.sha256(tessera.encode()).hexdigest()

    r = s.post("/idp/issue-token", json={"tessera_hash": tessera_hash, "eph_pubkey_spki": eph_spki})
    assert r.status_code == 200, ("issue-token", r.get_json())
    tok = r.get_json()
    token_string, token_sig = tok["token_string"], tok["token_sig"]

    ae_pub = load_der_public_key(base64.b64decode(tok["ae_pubkey_oaep"]))
    ct = ae_pub.encrypt(choice.encode(), OAEP)
    ct_b64 = base64.b64encode(ct).decode()
    tc = hashlib.sha256(ct).hexdigest()

    ballot_sig = base64.b64encode(eph.sign(
        (ct_b64 + "|" + token_string + "|" + token_sig).encode(), PSS, hashes.SHA256())).decode()

    r = s.post("/ae/submit-ballot", json={
        "ciphertext": ct_b64, "tracking_code": tc,
        "token_string": token_string, "token_sig": token_sig, "ballot_sig": ballot_sig})
    return r, tc, token_string

with app.app.test_client() as c:

    c.post("/admin/reset", json={})

    print("\n1) Gating durante le votazioni (scrutinio non concluso)")
    r = c.get("/bulletin-board")
    check("/bulletin-board mostra lo stato riservato", "riservata" in r.get_data(as_text=True))
    r = c.get("/verify/check?code=" + "a" * 64)
    check("/verify/check risponde 403 + locked", r.status_code == 403 and r.get_json().get("locked"))
    r = c.get("/bulletin-board/verify-chain")
    check("/verify-chain risponde 403 + locked", r.status_code == 403 and r.get_json().get("locked"))

    print("\n2) Flusso di voto completo (3 elettori)")
    plan = [("mrossi", "AB1234567", "SI"), ("lbianchi", "CD2345678", "NO"), ("gverdi", "EF3456789", "SI")]
    tcs = []
    for spid, tess, ch in plan:
        r, tc, token_string = client_vote(c, spid, "Referendum2026!", tess, ch)
        check(f"voto {spid} ({ch}) accettato", r.status_code == 200 and r.get_json().get("success"))
        tcs.append(tc)
        tok = json.loads(token_string)
        check(f"token di {spid} NON contiene voter_id", "voter_id" not in tok)

    print("\n3) Anti-doppio-voto: l'unicità è imposta ESCLUSIVAMENTE dall'AE")

    r = c.post("/auth/authenticate", json={"spid_id": "mrossi", "password": "Referendum2026!"})
    check("passo 1 (identità) superato anche dopo aver votato", r.status_code == 200)
    r = c.post("/auth/verify-tessera", json={"tessera": "AB1234567"})
    check("passo 2 (tessera) NON blocca più il ri-voto (IdP cieco sui nullifier)", r.status_code == 200)
    r = c.post("/idp/issue-token", json={
        "tessera_hash": hashlib.sha256(b"AB1234567").hexdigest(),
        "eph_pubkey_spki": base64.b64encode(
            rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()})
    check("emissione token consentita dall'IdP anche al secondo tentativo", r.status_code == 200)

    r, _, _ = client_vote(c, "mrossi", "Referendum2026!", "AB1234567", "NO")
    check("ri-voto bloccato dall'AE in /ae/submit-ballot (409)", r.status_code == 409)
    check("il rifiuto cita il doppio voto", "oppio voto" in (r.get_json() or {}).get("error", ""))

    print("\n4) La verifica resta riservata prima dello scrutinio")
    r = c.get("/verify/check?code=" + tcs[0])
    check("tracking code reale non verificabile durante le votazioni", r.status_code == 403)

    print("\n5) Scrutinio con schema a soglia (3 frammenti su 5)")
    threshold = json.load(open("keys/threshold_shares.json"))
    shares = [{"x": s["share_id"], "y": s["share_value"]} for s in threshold["shares"][:3]]
    r = c.post("/admin/decrypt", json={"shares": shares})
    res = r.get_json()
    check("scrutinio completato", r.status_code == 200 and res.get("success"))
    if res.get("success"):
        counts = res["results"]["counts"]
        check("conteggio corretto (SI=2, NO=1)", counts.get("SI") == 2 and counts.get("NO") == 1)
        print("     risultati:", counts, "totale:", res["results"]["total_ballots"])

    print("\n6) Sblocco a scrutinio concluso")
    r = c.get("/bulletin-board")
    body = r.get_data(as_text=True)
    check("/bulletin-board ora mostra i risultati", "Scrutinio completato" in body and "riservata" not in body)
    r = c.get("/verify/check?code=" + tcs[0])
    j = r.get_json()
    check("tracking code reale ora verificabile (found)", r.status_code == 200 and j.get("found"))
    r = c.get("/verify/check?code=" + "f" * 64)
    check("tracking code inesistente -> not found", r.status_code == 200 and not r.get_json().get("found"))
    r = c.get("/bulletin-board/verify-chain")
    check("hash chain integra", r.status_code == 200 and r.get_json().get("valid"))


print(f"\n=== RISULTATO: {ok} OK, {fail} FAIL ===")
exit(1 if fail else 0)
