# SPOTTER
## Continuous OSINT & Red Team Recon Platform

Self-hosted, operator-facing intelligence platform for authorized red team engagements. Ingests data from Cobalt Strike, SharpHound/BloodHound, nmap, Amass, Flare.io, CSV, and plain-text recon; correlates everything into interactive Individual dossiers in a Neo4j-backed graph via **Flowsint**; runs a continuous OODA Loop through **n8n** automation workflows; and provides a natural-language query interface via **Open WebUI + Ollama**.

> **Authorization required.** Designed for use under documented Rules of Engagement on authorized engagements only.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Data Sources                                               │
│  CS Team Server · SharpHound ZIPs · nmap XML · Amass · CSV │
│  Flare.io breach data · Plain-text pastes                   │
└──────────────────┬──────────────────────────────────────────┘
                   │  n8n webhooks / scheduled polls
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  n8n Workflow Engine  (11 workflows)                        │
│  Ingest → Enrich → Analyze → Alert → Export                 │
└──────┬──────────────────────────┬───────────────────────────┘
       │ Flowsint REST API        │ Neo4j Cypher
       ▼                          ▼
┌──────────────┐        ┌─────────────────────┐
│   Flowsint   │◄──────►│      Neo4j          │
│  Graph UI    │        │  (graph storage)    │
└──────────────┘        └─────────────────────┘
       │
       │ LLM tools
       ▼
┌─────────────────────────────────────────────────────────────┐
│  Open WebUI  ◄──►  Ollama  (local LLM inference)           │
│  SecurityLLM · file upload · natural-language graph queries │
└─────────────────────────────────────────────────────────────┘

Sidecars:  maigret-api (OSINT username search)
           titus-sidecar (credential pattern scanner)
```