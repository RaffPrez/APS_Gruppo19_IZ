# Sistema di e-voting referendario - Prototipo didattico Gruppo_19_IZ

Questo repository contiene un prototipo di sistema di voto elettronico (E-Voting) sviluppato per l'insegnamento di **Algoritmi e Protocolli per la Sicurezza (A.A. 2025/2026)**. Il sistema implementa un protocollo sicuro basato sulla separazione dei domini tra Identity Provider (IdP) e Autorità Elettorale (AE), l'uso di chiavi effimere e un registro pubblico immutabile strutturato come una catena di hash. La chiave privata dell'AE è protetta tramite uno schema di condivisione del segreto a soglia (t=3, n=5).

## Prerequisiti
Prima di iniziare, assicurati di avere installato sul tuo sistema:
* **Python 3.8 o superiore**
* Il gestore di pacchetti `pip`

## 1. Installazione delle dipendenze
Il progetto utilizza i framework **Flask** per la gestione del server web e delle API, e **Cryptography** per l'intera suite di operazioni crittografiche (RSA-OAEP, RSA-PSS, AES-256-GCM, Scrypt, Shamir's Secret Sharing).

Installa i pacchetti richiesti eseguendo il seguente comando nel terminale:

    pip install flask cryptography


## 2. Inizializzazione del sistema (Generazione chiavi e DB)
Prima di avviare il server, è **obbligatorio** eseguire lo script di setup. Questo script si occupa di configurare l'ambiente iniziale, eseguendo i seguenti passi:
1. Generazione delle chiavi RSA a 2048-bit per l'IdP.
2. Generazione delle chiavi RSA a 2048-bit per l'AE.
3. Cifratura della chiave privata AE con AES-256-GCM e successiva divisione della chiave AES in 5 frammenti crittografici distribuiti a 5 commissari distinti, stabilendo una soglia minima di 3 frammenti per la ricostruzione.
4. Generazione del database di test dei cittadini, convertendo le password in hash salati.
5. Configurazione del quesito referendario e azzeramento dell'urna digitale pubblica.

Esegui lo script con il comando:

    python setup_keys.py

Al termine dell'esecuzione, verranno create automaticamente le cartelle `keys/` e `data/` contenenti tutti i file di configurazione necessari al funzionamento del prototipo.


## 3. Avvio del server
Una volta completato il setup crittografico, puoi avviare l'applicazione web Flask eseguendo lo script principale:

    python app.py

Il server si avvierà in modalità locale. Puoi accedere all'interfaccia del simulatore aprendo il browser e navigando all'indirizzo: **http://localhost:5001**

## 4. Esecuzione dei test end-to-end
Il progetto include una suite completa di test automatizzati che simula l'intero ciclo di vita di una consultazione elettorale: tentativi di doppio voto, blind-token validation, verifica dell'immutabilità della catena di hash prima e dopo la chiusura del voto, e ricostruzione a soglia della chiave AE per lo scrutinio.

Per eseguire i test ed accertarsi della correttezza logica del protocollo, esegui:

    python test_e2e.py

## 5. Analisi delle prestazioni
Il progetto include uno script di benchmark per misurare i tempi di esecuzione delle singole operazioni crittografiche impiegate nel protocollo e per analizzare le dimensioni in byte dei vari payload.
**Nota:** Questo script necessita delle chiavi di sistema per poter funzionare, assicurati quindi di aver già eseguito il punto 2.

Per avviare la misurazione delle performance, esegui:

    python benchmark_temp.py

L'output mostrerà nel terminale i tempi medi in millisecondi di ciascuna operazione e il peso in byte di firme, crittogrammi e token JSON.