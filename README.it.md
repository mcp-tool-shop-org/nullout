<p align="center">
  <a href="README.ja.md">日本語</a> | <a href="README.zh.md">中文</a> | <a href="README.es.md">Español</a> | <a href="README.fr.md">Français</a> | <a href="README.hi.md">हिन्दी</a> | <a href="README.md">English</a> | <a href="README.pt-BR.md">Português (BR)</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/mcp-tool-shop-org/brand/main/logos/nullout/readme.png" width="400" alt="NullOut">
</p>

<p align="center">
  <a href="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml"><img src="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/mcp-tool-shop-org/nullout"><img src="https://codecov.io/gh/mcp-tool-shop-org/nullout/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/mcp-tool-shop-org/nullout/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
  <a href="https://mcp-tool-shop-org.github.io/nullout/"><img src="https://img.shields.io/badge/Landing_Page-live-blue" alt="Landing Page"></a>
</p>

Un server MCP che individua e rimuove in modo sicuro i file "indelebili" su Windows.

Windows riserva nomi di dispositivo come `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9` e `LPT1`-`LPT9` a livello Win32. I file con questi nomi possono esistere su NTFS (creati tramite WSL, strumenti Linux o API di basso livello), ma diventano impossibili da rinominare, spostare o eliminare tramite Esplora file o comandi shell standard.

NullOut esegue la scansione di queste voci potenzialmente dannose e le rimuove in modo sicuro utilizzando lo spazio dei nomi esteso `\\?\`, con un flusso di lavoro di conferma in due fasi progettato per gli host MCP.

## Come funziona

1. **Scansiona** una directory specificata per conflitti di nomi riservati, punti/spazi finali e percorsi troppo lunghi.
2. **Pianifica** la pulizia: NullOut genera un token di conferma univoco per ogni voce, legato all'identità del file (numero di serie del volume + ID del file).
3. **Elimina** utilizzando il token: NullOut verifica nuovamente che il file non sia cambiato (protezione TOCTOU) prima di rimuoverlo tramite lo spazio dei nomi esteso.

## Modello di sicurezza

- **Solo directory specificate** — le operazioni sono limitate alle directory che si configurano esplicitamente.
- **Nessun percorso diretto nelle operazioni distruttive** — l'eliminazione accetta solo gli ID di ricerca generati dal server e i token di conferma.
- **Politica deny_all per i punti di rianalisi** — le connessioni, i collegamenti simbolici e i punti di mount non vengono mai attraversati o eliminati.
- **Associazione dell'identità del file** — i token sono firmati con HMAC e associati al numero di serie del volume + ID del file; qualsiasi modifica tra la scansione e l'eliminazione viene rifiutata.
- **Solo directory vuote** — la versione 1 si rifiuta di eliminare directory non vuote.
- **Errori strutturati** — ogni errore restituisce un codice leggibile dalla macchina, con suggerimenti per il passaggio successivo.

## Strumenti MCP

| Strumento | Tipo | Scopo |
|------|------|---------|
| `list_allowed_roots` | solo lettura | Mostra le directory di scansione configurate. |
| `scan_reserved_names` | solo lettura | Trova voci potenzialmente dannose in una directory. |
| `get_finding` | solo lettura | Ottieni i dettagli completi di una voce. |
| `plan_cleanup` | solo lettura | Genera un piano di eliminazione con token di conferma. |
| `delete_entry` | distruttivo | Elimina un file o una directory vuota (richiede un token). |
| `who_is_using` | solo lettura | Identifica i processi che bloccano un file (Gestore del riavvio). |
| `get_server_info` | solo lettura | Metadati del server, politiche e funzionalità. |

## Configurazione

Imposta le directory di scansione tramite variabile d'ambiente:

```
NULLOUT_ROOTS=C:\Users\me\Downloads;C:\temp\cleanup
```

Segreto per la firma dei token (genera un valore casuale):

```
NULLOUT_TOKEN_SECRET=your-random-secret-here
```

## Modello di minaccia

NullOut protegge da:

- **Uso improprio distruttivo** — l'eliminazione richiede un token di conferma generato dal server; non vengono accettati percorsi diretti.
- **Attraversamento di percorsi** — tutte le operazioni sono limitate alle directory specificate; le sequenze di escape ".." vengono risolte e rifiutate.
- **Escape dai punti di rianalisi** — le connessioni, i collegamenti simbolici e i punti di mount non vengono mai attraversati o eliminati (deny_all).
- **Race condition TOCTOU** — i token sono associati tramite HMAC al numero di serie del volume + ID del file; qualsiasi modifica dell'identità tra la scansione e l'eliminazione viene rifiutata.
- **Trucchi dello spazio dei nomi** — le operazioni distruttive utilizzano il prefisso esteso del percorso `\\?\` per aggirare l'analisi dei nomi Win32.
- **File bloccati** — l'attribuzione al Gestore del riavvio è in sola lettura; NullOut non termina mai i processi.
- **Directory non vuote** — rifiutate dalla politica; è possibile eliminare solo le directory vuote.

**Dati a cui si accede:** metadati del file system (nomi, ID dei file, numeri di serie del volume), metadati dei processi (PID, nomi delle applicazioni tramite Gestore del riavvio).
**Dati a cui NON si accede:** contenuto dei file, rete, credenziali, registro di Windows.
**Non vengono raccolti né inviati dati di telemetria**.

## Requisiti

- Windows 10/11
- Python 3.10+

---

Creato da <a href="https://mcp-tool-shop.github.io/">MCP Tool Shop</a
