# AGENTS.md

## Contesto

Za è un micro-agente Linux in un singolo file Python. Leggi `README.md` e
`requirements.txt` prima di modificarlo. `za.py` contiene entrypoint, database,
scanner, ricerca, client FreeLLMAPI, esecuzione controllata e self-test; non ci
sono moduli applicativi separati né dipendenze Python esterne.

## Flusso e invarianti

1. `SystemScanner` indicizza applicazioni e metadati rigenerabili nel database
   SQLite specifico della macchina.
2. `ApplicationResolver` e `SkillStore` cercano prima risultati deterministici;
   la normalizzazione usa `SYNONYM_GROUPS` per equivalenze italiano/inglese.
3. Solo se non esiste una procedura riutilizzabile, `FreeLLMAPIEngine` invia la
   richiesta a `http://127.0.0.1:3001/v1/chat/completions` con modello `auto`.
   Za non avvia il gateway: `freellmapi.service` gestisce al boot l'installazione
   Docker Compose attesa in `~/freellmapi`.
4. La chiave viene letta esclusivamente dal portachiavi tramite `secret-tool`,
   attributi `application=freellmapi` e `account=default`; se manca viene chiesta
   con input nascosto e salvata. Non usare file di configurazione o variabili
   d'ambiente per la credenziale.
5. Ogni proposta resta visibile, modificabile e soggetta ad approvazione prima
   dell'esecuzione. Non indebolire controlli sui percorsi, redazione dei segreti,
   classificazione del rischio o feedback post-esecuzione.
6. Per una proposta caricata da una skill, il prompt accetta `d` e cancella la
   procedura senza eseguirla. `SkillStore.delete` elimina skill e versioni ma
   conserva la cronologia delle esecuzioni, impostandone `skill_id` a `NULL`.

Non reintrodurre modelli locali, download di pesi, cache Hugging Face, backend
GGUF/llama.cpp, Transformers o diagnostica GPU.

## Mappa delle modifiche

- Client API, keyring, sinonimi, database, CLI e comportamento runtime: `za.py`.
- Requisiti, uso, credenziali e comandi pubblici: `README.md`.
- Dipendenze Python: `requirements.txt` (attualmente nessuna).
- Avvio automatico del gateway FreeLLMAPI: `freellmapi.service`.

Quando cambiano architettura, configurazione pubblica, invarianti di sicurezza o
comandi di verifica, sincronizza `README.md` e questo file.

## Verifica obbligatoria

Esegui dalla radice del progetto:

```bash
python3 -m py_compile za.py
./za.py --self-test
./za.py --help
systemd-analyze --user verify freellmapi.service
```

I self-test devono usare directory temporanee e mock per FreeLLMAPI e keyring:
non devono inviare richieste LLM, leggere credenziali reali o eseguire azioni
distruttive. Il lavoro è completo quando i controlli passano, il diff non
contiene credenziali e documentazione e comportamento coincidono.
