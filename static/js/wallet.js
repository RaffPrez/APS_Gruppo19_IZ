const Wallet = (() => {
  let ephemeralKeyPair = null;
  let tokenData = null;

  function ab2b64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  function b642ab(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
  }

  function ab2hex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async function generateEphemeralKeys() {
    // genero una coppia di chiavi RSA usa-e-getta, valida solo per questo voto
    ephemeralKeyPair = await crypto.subtle.generateKey(
      { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"]
    );
    console.log("[Wallet] Chiavi effimere RSA-PSS 2048-bit generate");
  }

  async function exportEphemeralPublicKey() {
    const spki = await crypto.subtle.exportKey("spki", ephemeralKeyPair.publicKey);
    return ab2b64(spki);
  }

  async function hashTessera(tesseraNumber) {
    // impronta della tessera (SHA-256): cosi' la tessera non viaggia mai in chiaro
    const data = new TextEncoder().encode(tesseraNumber);
    const h = await crypto.subtle.digest("SHA-256", data);
    return ab2hex(h);
  }

  async function getAuthorizationToken(tesseraNumber) {
    await generateEphemeralKeys();
    const tesseraHash = await hashTessera(tesseraNumber);
    const ephPubKeySpki = await exportEphemeralPublicKey();

    console.log("[Wallet] tessera_hash:", tesseraHash.slice(0, 20) + "...");
    console.log("[Wallet] Invio {tessera_hash, eph_pubkey_spki} all'IdP...");

    // invio all'IdP solo l'impronta della tessera e la chiave pubblica usa-e-getta
    const resp = await fetch("/idp/issue-token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tessera_hash: tesseraHash, eph_pubkey_spki: ephPubKeySpki }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.error || "Errore nel rilascio del token");
    }

    tokenData = await resp.json();
    console.log("[Wallet] Token ricevuto dall'IdP — sessione IdP chiusa");
    return tokenData;
  }

  async function encryptVote(voteChoice, aePubKeySpkiB64) {
    // carico la chiave PUBBLICA dell'AE (serve solo a cifrare)
    const aePubKey = await crypto.subtle.importKey(
      "spki", b642ab(aePubKeySpkiB64),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false, ["encrypt"]
    );
    const voteBytes = new TextEncoder().encode(voteChoice);   // voto -> byte
    // cifro il voto con RSA-OAEP: solo l'AE potra' leggerlo; OAEP aggiunge casualita'
    const ctBuf = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, aePubKey, voteBytes);
    console.log("[Wallet] Voto cifrato con RSA-OAEP (chiave pubblica AE)");
    return { ctBuf, ctB64: ab2b64(ctBuf) };
  }

  async function generateTrackingCode(ctBuf) {
    // codice di verifica = hash del voto CIFRATO (non del voto): non rivela la scelta
    const h = await crypto.subtle.digest("SHA-256", ctBuf);
    const tc = ab2hex(h);
    console.log("[Wallet] Tracking code:", tc.slice(0, 20) + "...");
    return tc;
  }

  async function signBallot(ctB64, tokenString, tokenSig) {
    // unisco i tre pezzi della scheda: voto cifrato + token + firma dell'IdP
    const toSign = new TextEncoder().encode(ctB64 + "|" + tokenString + "|" + tokenSig);
    // firmo con la chiave usa-e-getta del votante (RSA-PSS): prova che la scheda e' sua
    const sigBuf = await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      ephemeralKeyPair.privateKey,
      toSign
    );
    console.log("[Wallet] Scheda firmata con chiave effimera RSA-PSS");
    return ab2b64(sigBuf);
  }

  async function castVote(voteChoice) {
    if (!tokenData || !ephemeralKeyPair)
      throw new Error("Wallet non inizializzato — effettuare prima l'autenticazione");

    const { token_string, token_sig, ae_pubkey_oaep } = tokenData;

    const { ctBuf, ctB64 } = await encryptVote(voteChoice, ae_pubkey_oaep);
    const trackingCode     = await generateTrackingCode(ctBuf);
    const ballotSig        = await signBallot(ctB64, token_string, token_sig);

    const resp = await fetch("/ae/submit-ballot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "omit",   // niente cookie: l'AE non puo' collegare la scheda all'identita'
      body: JSON.stringify({
        ciphertext:    ctB64,
        tracking_code: trackingCode,
        token_string:  token_string,
        token_sig:     token_sig,
        ballot_sig:    ballotSig,
      }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.error || "Errore nel deposito della scheda");
    }

    const result = await resp.json();

    ephemeralKeyPair = null;   // cancello le chiavi usa-e-getta dalla memoria
    tokenData = null;
    console.log("[Wallet] Chiavi effimere eliminate dalla memoria");

    return { ...result, tracking_code: trackingCode };
  }

  return { getAuthorizationToken, castVote };
})();
