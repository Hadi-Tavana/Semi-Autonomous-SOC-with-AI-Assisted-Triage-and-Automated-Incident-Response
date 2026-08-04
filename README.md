<img width="1024" height="735" alt="davinci_wide_cinematic_panoramic_banner__anime_cartoon_ill" src="https://github.com/user-attachments/assets/43d6393a-2c36-4e67-a870-afdd3cb61e9d" />


# Semi-Autonomous-SOC-with-AI-Assisted-Triage-and-Automated-Incident-Response

*A SIEM, a SOAR, and a locally-hosted AI walk into a firewall. Nobody's paged at 3 AM.*

---

## What is this

This is the workflow export and automation logic behind a semi-autonomous Security Operations Center we built as a home-lab-meets-capstone project. Short version: alerts come in from a firewall and a couple of Windows endpoints, get normalized into one shape, enriched with real threat intelligence, handed to a local LLM for triage, scored by a rule-based risk engine, and if things look bad enough, the system isolates the host, deletes the malware, and blocks the IP, all before a human has finished their coffee.

We then pointed a real multi-stage red team engagement at it (recon → webshell → privesc → persistence → Kerberoasting → lateral movement → data exfil) to see if any of this actually held up under pressure. Spoiler: it mostly did, and we wrote 15,000+ words about exactly how and where.

No commercial platforms. No cloud AI. Just open-source tools, a 7B-parameter model running on a spare PC, and enough n8n nodes to make a spaghetti diagram blush.

## The technical writeup

We wrote a 3-part series covering the whole build in way more depth than a README can hold:

1. **Part 1: Detection & Ingestion**: how alerts get generated across three different sources and normalized into one pipeline → *https://medium.com/@edrishassani526/building-a-semi-autonomous-soc-part-1-detection-ingestion-ab9596f43852*
2. **Part 2: AI-Assisted Triage & Risk Scoring**: OSINT enrichment, the local LLM, and the six-factor risk engine that decides what's actually serious → *https://medium.com/@edrishassani526/building-a-semi-autonomous-soc-part-2-ai-assisted-triage-risk-scoring-caa498fdb891*
3. **Part 3: Automated Response & Red Team Results**: host isolation, file deletion, IP/domain blocking, and what happened when we actually attacked our own lab → *https://medium.com/@edrishassani526/building-a-semi-autonomous-soc-part-3-automated-response-red-team-results-ccc828a1ceb5*


## What's actually in here

-  **n8n workflow exports:** the main ingestion pipeline, the AI Agent subworkflow, the OSINT dispatcher subworkflows (IP / Domain / Hash / CVE), and every response-track workflow (isolation, file deletion, IP blocking, domain blocking)
-  **JavaScript node logic:** dropped in one file at a time in [`/js-nodes`](./js-nodes), since a 150-line normalization function inside a tiny n8n code box is not exactly a pleasant reading experience otherwise
-  **Velociraptor artifacts & scripts:** the custom VQL artifacts and the Python wrappers around them (hash hunting, quarantine, remediation)

## The stack, for the impatient

`Security Onion 2` · `OPNsense` · `n8n` · `TheHive 4` · `Cortex` · `Velociraptor` · `Qwen2.5 (Ollama)` · `Mattermost` · `MongoDB` · `Caldera` (for red teaming, not defense — don't get any ideas)


## Who broke made this

**<a href="https://github.com/Edris526">Edris Hassani</a>** & **<a href="https://github.com/Hadi-Tavana/Hadi-Tavana">Hadi Tavana</a>**

Questions, bug reports, or "why on earth did you do it this way", open an issue, or find us in the comments on the Medium series.

---

*If you use any part of this in your own lab: cool, go for it. If you use it against a network you don't own: not cool, go build your own lab like we did.*

