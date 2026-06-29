# Building a PII / Sensitive-Data Discovery Agent for Snowflake: Landscape, Architecture & Insurance Compliance

## TL;DR
- **Build a hybrid agent, don't buy a black box, and anchor it on Snowflake-native primitives.** The most robust and cost-effective design for a P&C insurer on Snowflake is an event-driven agent that uses Snowflake's native classification (SYSTEM$CLASSIFY, custom classifiers, classification profiles) plus a layered classifier (column-name heuristics → regex/dictionary → sampled-value inspection → LLM tie-breaker via Cortex AI_CLASSIFY), writes results to object tags, and lets **tag-based masking/tokenization policies auto-apply** so protection follows the tag, not a manual step.
- **The commercial landscape splits into three categories** you can mix: DSPM/classification platforms (BigID, Securiti, Cyera, Sentra, Immuta, Privacera, Collibra, Microsoft Purview), Snowflake-native governance (Horizon Catalog, automatic classification, Cortex), and tokenization providers that plug into Snowflake External Tokenization (Protegrity, ALTR, Skyflow, Thales, Fortanix, Baffle). Native + a tokenization vendor covers most insurer needs; a full DSPM is justified when you must scan unstructured claims files and non-Snowflake sources too.
- **Classification is only valuable if it maps to controls and evidence.** For a US insurer, tag taxonomy should drive GLBA Safeguards, HIPAA (PHI in health/WC/liability claims), the NAIC Insurance Data Security Model Law (Model #668) / NY DFS 23 NYCRR 500 (which explicitly require "data governance and classification"), PCI DSS (cardholder data), and state privacy laws (CCPA/CPRA). Tags become the audit evidence that you know where Nonpublic Information lives and that it is masked/tokenized/access-controlled.

## Key Findings

1. **Snowflake's native classification is now a viable backbone, not just a helper.** Automatic sensitive data classification (announced November 18, 2024; generally available starting March 2025) lets you attach a *classification profile* to a database or schema; Snowflake then classifies existing and newly arriving tables/views on a schedule, assigns two system tags (`SNOWFLAKE.CORE.SEMANTIC_CATEGORY` for the data type and `SNOWFLAKE.CORE.PRIVACY_CATEGORY` for sensitivity: IDENTIFIER / QUASI_IDENTIFIER / SENSITIVE), and can auto-map those to your own user-defined tags. Snowflake's "Cortex Code Governance Skills" engineering blog states the native SYSTEM$CLASSIFY function "detects more than 150 sensitive data categories including emails, phone numbers, SSNs and addresses." Requires Enterprise Edition or higher.

2. **Tag-based masking is the architectural keystone.** You write a masking policy once, assign it to a tag with `ALTER TAG … SET MASKING POLICY`, and every column that ever receives that tag — now or in the future — is automatically protected when its data type matches the policy signature. This eliminates per-column manual application and is what makes an autonomous tagging agent safe: classification → tag → protection is a closed loop.

3. **A layered/ensemble classifier beats any single technique.** Column-name heuristics are cheap but miss cryptically named columns; regex/dictionary matching is precise for structured identifiers (SSN, credit card with Luhn checksum, VIN, email) but blind to free text; sampled-value statistical inspection catches mislabeled columns; NER/ML (Presidio + spaCy) and LLMs (Cortex AI_CLASSIFY) handle ambiguous or contextual cases. Microsoft Research's WSDM '24 paper "Table Meets LLM: Can Large Language Models Understand Structured Table Data?" (Sui, Zhou et al.) found that even with the best prompt configuration — HTML markup with format explanations and role prompts — GPT-3.5/GPT-4 reached only **65.43% overall accuracy** across seven basic table-understanding tasks on the SUC benchmark. So LLMs should be a *tie-breaker and metadata reasoner*, not the primary scanner.

4. **Insurance data is unusually broad in sensitivity** — it spans PII (name, SSN/TIN, DOB, driver's license, address), financial NPI (bank/account/card, premium and payout amounts), PHI in health/workers-comp/liability claims (diagnoses, ICD-10 codes, injury and treatment data), and quasi-identifiers (VIN, vehicle, beneficiary). This means a single "PII=true" tag is inadequate; you need a multi-dimensional taxonomy (category × regulation × sensitivity tier).

5. **Compliance regimes increasingly mandate classification itself.** NY DFS 23 NYCRR 500.03(b) and the NAIC Model Law require a written cybersecurity policy whose required areas are listed verbatim as "(a) information security (b) data governance and classification (c) asset inventory and device management…"; the FTC's amended GLBA Safeguards Rule (compliance deadline June 9, 2023) requires a written risk assessment and inventory of customer information; HIPAA requires safeguards for PHI. Tagging is the operational mechanism that satisfies "know where your Nonpublic Information is."

## Details

### PART 1 — Landscape Survey

#### Snowflake-native capabilities
- **Automatic sensitive data classification / classification profiles.** Create a `CLASSIFICATION_PROFILE` (an instance of the class in a governance schema) and set it on a database or schema with `ALTER DATABASE … SET CLASSIFICATION_PROFILE = …`. The profile controls cadence (`minimum_object_age_for_classification_days`, `maximum_classification_validity_days`), whether to `auto_tag`, whether to classify views (`classify_views`, off by default and potentially much costlier), and a `column_tag_map` to translate semantic categories into your own tags. Setting it at database level (GA from March 2025) means newly created tables are picked up automatically; classification doesn't start until ~1 hour after the profile is set.
- **SYSTEM$CLASSIFY / SYSTEM$CLASSIFY_SCHEMA.** One-shot stored procedures to classify a table or whole schema and optionally `{'auto_tag': true}`. Sample size is configurable from **1 to 10,000 rows** (default 10,000); Snowflake notes 10,000 is "typically more than enough to determine the category of a column." Results land in `SNOWFLAKE.ACCOUNT_USAGE.DATA_CLASSIFICATION_LATEST` and via `SYSTEM$GET_CLASSIFICATION_RESULT`. Each result carries `confidence` (e.g., HIGH), `coverage`, `semantic_category`, `privacy_category`, and `valid_value_ratio`.
- **Custom classifiers.** `CREATE SNOWFLAKE.DATA_PRIVACY.CUSTOM_CLASSIFIER <name>()` then `<name>!ADD_REGEX(SEMANTIC_CATEGORY, PRIVACY_CATEGORY, VALUE_REGEX, COL_NAME_REGEX, DESCRIPTION, THRESHOLD)`. The docs' worked example detects ICD-10 codes (`[A-TV-Z][0-9][0-9AB]\.?[0-9A-TV-Z]{0,4}`) and 6-digit employee IDs (`^[0-9]{6}$` with `COL_NAME_REGEX => 'EMP.*ID.*'`, `THRESHOLD => 0.8`). This is how you encode insurance-specific patterns (policy numbers, claim numbers, VIN, NAIC codes). The scoring algorithm uses match percentage and a per-instance THRESHOLD; ties are resolved by match percentage then alphabetical order. Pass classifiers to `SYSTEM$CLASSIFY` via `{'auto_tag':true,'custom_classifiers':['name']}` or `{'use_all_custom_classifiers':true}`.
- **Object tags + tag-based masking/row access.** Tags are key-value metadata on databases/schemas/tables/columns with inheritance. Masking policy example: `CREATE MASKING POLICY pii_mask AS (val string) RETURNS string -> CASE WHEN CURRENT_ROLE() IN ('PII_ALLOWED') THEN val ELSE '***MASKED***' END;` then `ALTER TAG pii_data SET MASKING POLICY pii_mask;`. A tag supports one masking policy per data type. A directly-assigned column policy takes precedence over a tag-based one. Setting a tag-based policy at database/schema level auto-protects columns in all newly added tables when the data type matches. Row access policies are assigned to tables (not tags) but can read a table's tag via `SYSTEM$GET_TAG_ON_CURRENT_TABLE` — useful for restricting claims rows to the handling adjuster/region via a mapping table and `IS_ROLE_IN_SESSION()`.
- **External tokenization.** Masking policies that call external functions to tokenize/detokenize via a partner. Snowflake lists partners: ALTR, Baffle, Capital One Databolt, Comforte, Fortanix, MicroFocus/OpenText Voltage, Protegrity, Privacera, SecuPI, Skyflow, Spring Labs, Thales. An external-tokenization masking policy can itself be assigned to a tag (tag-based external tokenization). Enterprise Edition required.
- **Snowflake Horizon Catalog** unifies classification, tags, masking/row policies, lineage, data quality, and AI guardrails (which "detect, redact and block PII from agent outputs before they reach users"). **Cortex** provides in-perimeter LLMs (AI_CLASSIFY, AI_REDACT, AI_COMPLETE, AI_FILTER) and **Cortex Agents** (a fully managed agentic platform that plans, calls tools, executes code in a sandbox, and reflects — all governed by Snowflake RBAC, "without requiring you to build or operate your own orchestration loop"). **Cortex Code Governance Skills** can generate classification/masking policies from natural language and score governance maturity across Classify/Protect/Monitor pillars.
- **Cortex AI_CLASSIFY** signature: `AI_CLASSIFY(<input>, <list_of_categories> [, <config_object>] [, <return_error_details>])`. Supports **multi-label** via `{'output_mode':'multi'}`, up to 500 labels, optional per-label `description`, a `task_description` (≤50 words), and few-shot `examples`. Returns `{"labels":[...]}`. Requires the SNOWFLAKE.CORTEX_USER role; token-based cost. It is the successor to CLASSIFY_TEXT. Docs caution that exceeding ~20 categories may reduce accuracy.
- **Cortex AI_REDACT** (generally available, late 2025) "uses a large language model (LLM) to help you detect, locate, and redact PII from unstructured text data." Modes `redact` (default, replaces with `[NAME]`, `[ADDRESS]`, …) and `detect` (returns spans with category/start/end/text for selective/allowlist redaction). Its docs enumerate **12 named categories** with sub-types: NAME, EMAIL, PHONE_NUMBER, DATE_OF_BIRTH, GENDER, AGE, ADDRESS, NATIONAL_ID (US SSN), PASSPORT, TAX_IDENTIFIER, PAYMENT_CARD_DATA, DRIVERS_LICENSE, IP_ADDRESS. Input+output ≤ 4,096 tokens (chunk longer text with SPLIT_TEXT_RECURSIVE_CHARACTER). Ideal for adjuster notes and claims free-text columns.

**Native strengths/limits.** Strengths: in-perimeter (no data egress), tightly integrated with tags/policies, no extra licensing beyond Enterprise/Cortex, serverless. Limits: structured Snowflake data only (no S3/SaaS/unstructured estate beyond Cortex on text columns); credit cost scales with column count (and heavily with views); ~1-hour latency before auto-classification kicks in; native categories are general (you must add custom classifiers for insurance specifics); profile object limits apply (not directly on >10,000 schemas; tables with >10,000 columns cannot be auto-classified).

#### Commercial data classification / DSPM / governance tools
- **BigID** — privacy/governance-led ML classification; first Snowflake partner validated in both Data Security and Data Catalog categories under the Snowflake Ready Technology Validation program; natively detects new/changed data, classifies structured + unstructured + "dark data," enriches Snowflake object tags, and instructs Snowflake to apply Dynamic Data Masking and row access policies. Strong for DSAR/CCPA/GDPR-driven programs; classification accuracy on cloud-native sources is competitive but, per multiple 2026 comparisons, not always category-leading versus cloud-first DSPMs.
- **Immuta** — data-centric, policy-as-code/ABAC; automated sensitive data discovery auto-tags `Discovered.PII`; dynamic masking, k-anonymity, purpose-based access; deep Snowflake integration. Best when you want one ABAC policy engine governing many platforms and privacy-enhancing technologies for data science. Immuta reports customers reducing time-to-access "from months to seconds."
- **Privacera** — Apache Ranger-based, unified access governance/ABAC across Snowflake, Databricks, AWS; best for fragmented multi-cloud lakehouse policy enforcement; can be heavy for single-platform shops.
- **Securiti** — "Data Command Center" unifying DSPM + privacy + governance + AI security; strong compliance automation and SaaS coverage; good all-in-one for multi-regulation insurers.
- **Cyera** — agentless cloud-native DSPM; widely cited as a 2024–2026 market leader on classification accuracy; uses LLMs for data context; scans Snowflake, S3, BigQuery, etc.; identifies "toxic combinations" (sensitive + over-privileged + stale). Surfaces risk but doesn't itself enforce encryption/retention.
- **Sentra** — cloud-native DSPM that runs discovery/classification inside the customer's VPC (data-sovereignty friendly), integrates with Microsoft Purview labels; recognized as a Leader/Fast Mover in the GigaOm DSPM Radar; strong at petabyte-scale efficiency.
- **Microsoft Purview** — strong inside Microsoft 365/Azure with native labeling/DLP; coverage drops sharply outside the Microsoft estate (thin on Snowflake/Databricks/BigQuery DBaaS), so multicloud insurers usually pair it with a cloud-native DSPM for Snowflake.
- **Collibra / Alation / Atlan** — catalog/governance and metadata management; classification and stewardship workflows; Atlan positions as a cross-platform context layer extending Horizon governance (named a Leader in the 2026 Gartner MQ for D&A Governance).
- **Open Raven, Varonis, Concentric AI** — DSPM/data-security; Varonis strongest for on-prem file shares + M365 behavioral analytics and access governance, lighter on cloud DBaaS classification.

#### Open-source classification tools
- **Microsoft Presidio** — context-aware PII framework: AnalyzerEngine combines regex + checksums + spaCy/HuggingFace NER + context-aware scoring across configurable recognizers; AnonymizerEngine redacts/masks/hashes/encrypts; runs as Python or HTTP service (PySpark/Docker/K8s). Best for unstructured text and as a pluggable value-inspection layer in your agent. A common hybrid pattern: regex as a fast first-pass filter, then the more expensive NER model on remaining text to balance cost and accuracy.
- **Google Cloud Sensitive Data Protection (Cloud DLP)** — built-in infoType detectors (PII, SPII, GOVERNMENT_ID, DEMOGRAPHIC, credentials), custom infoTypes via regex, exclusion rules; de-identification transforms. Docs warn built-in detectors "are not a perfectly accurate detection method."
- **Amazon Macie** — managed S3 discovery with 100+ managed data identifiers (credentials, financial, PHI, PII), custom regex identifiers, allow lists; automated discovery samples objects daily and produces per-bucket sensitivity scores.
- **spaCy / Sherlock / SIMON** — NER and column-type detection models (Sherlock uses deep neural nets, SIMON a character-level CNN+LSTM); useful if you build your own ML column classifier.

#### Tokenization / masking platforms (External Tokenization)
- **Protegrity** — field-level encryption/tokenization/masking applied at ingestion; Snowflake masking policy invokes the Protegrity protector via external function/API Gateway (authorized by Snowflake's API integration object); vaultless tokenization; popular in BFSI for PCI/HIPAA scope reduction. A published bank case cited a 40% reduction in compliance-reporting effort.
- **ALTR** — cloud-to-cloud SaaS (no proxy); a service user creates/manages masking + row access policies and external functions; `ALTR_PROTECT_TOKENIZE`/`DETOKENIZE` external functions; tags databases `ALTR_GOVERNED`; recurring schema snapshots (every ~3 days) detect new objects.
- **Skyflow** — data-vault/PII vault with REST+SQL APIs; tokenize for compliance while keeping a searchable encrypted store; deployable in your VPC.
- **Thales (CipherTrust/Vormetric), Fortanix, Baffle, OpenText Voltage** — format-preserving encryption/tokenization with Snowflake external-tokenization integrations; Voltage emphasizes NIST FF1/SP 800-38G format-preserving methods and FIPS 140-2 certification.

### PART 2 — Design Patterns & Architecture (build-it-yourself)

#### Reference architecture (event-driven, Snowflake-centric)
1. **Detection of new/changed objects.** Snowflake has no traditional DDL triggers, so use one of:
   - **Metadata polling** of `SNOWFLAKE.ACCOUNT_USAGE.TABLES`/`COLUMNS` (account-wide, with ACCOUNT_USAGE latency) or per-database `INFORMATION_SCHEMA.COLUMNS` (low latency/real-time but per-DB), diffing against a watermark table of already-classified objects.
   - **Streams + triggered tasks** for *data* arrival: `CREATE TASK … WHEN SYSTEM$STREAM_HAS_DATA('stg_stream') AS CALL classify_sp();` Triggered tasks run only when the stream has data, skip with negligible cost otherwise (a nominal cloud-services charge per WHEN evaluation), can be serverless, and Snowflake runs a health check if a task hasn't run for 12 hours to prevent stream staleness. Note streams track DML, not DDL — pair with metadata polling for new-table detection.
   - **Classification profiles at database level** (simplest): let Snowflake auto-detect and classify new tables; your agent then reacts to new rows in `DATA_CLASSIFICATION_LATEST`.
   A robust pattern: a scheduled/triggered "scanner" task discovers un-classified columns → enqueues them → a "classifier" procedure processes the queue → a "tagger" applies tags → tag-based policies auto-protect.

2. **Agent loop (planner → scanner → classifier → tagger → action → review).**
   - *Planner*: determines scope (which DBs/schemas, new vs. re-validation due to `maximum_classification_validity_days`), budget, and warehouse size.
   - *Scanner*: enumerates target columns + metadata (name, data type, comment, parent table) and pulls a privacy-preserving value sample.
   - *Classifier*: runs the ensemble (below) and produces `{semantic_category, privacy_category, confidence, evidence}`.
   - *Tagger*: for confidence ≥ high threshold, applies tags via `ALTER TABLE … MODIFY COLUMN … SET TAG`.
   - *Action*: tag-based masking/tokenization auto-applies; optionally open a ticket/Slack alert; for regulated categories, add to a row-access mapping.
   - *Human-in-the-loop review*: medium-confidence results go to a steward queue (Snowsight Tags & policies UI or a Streamlit app); low-confidence are logged but not auto-tagged.
   This maps cleanly onto Cortex Agents if you prefer a managed loop, or a Snowpark stored procedure orchestrated by tasks if you prefer deterministic control.

3. **Confidence thresholds & feedback.** Use two thresholds: auto-tag (e.g., ≥0.9) and review (e.g., 0.6–0.9). Steward decisions feed a labeled table that (a) tunes regex/custom-classifier thresholds, (b) becomes few-shot examples for the LLM, and (c) is the benchmark for measuring drift.

#### Classification techniques & trade-offs
| Technique | Precision | Recall | Cost | Notes |
|---|---|---|---|---|
| Column-name heuristics | Med | Low–Med | Very low | Misses cryptic names (`f1`, `c_ssn_x`); first-pass only |
| Regex / checksum | High (structured) | Low (free text) | Low | SSN, card (Luhn), VIN, email, ICD-10; encode as custom classifiers |
| Dictionary/lookup | High | Med | Low | Names, cities, NAIC/diagnosis code sets |
| Sampled value stats | Med–High | Med | Med | Catches mislabeled columns; needs sampling guardrails |
| NER/ML (Presidio/spaCy) | Med–High | Med–High | Med | Best for unstructured/free text |
| LLM (Cortex AI_CLASSIFY) | Med–High | High (contextual) | Higher (tokens) | Tie-breaker & metadata reasoner; ~65% alone on naive table tasks |
| Hybrid ensemble | High | High | Med | Recommended: cheap filters first, LLM last |

#### Applying tags & triggering downstream protection (concrete SQL)
```sql
-- 1. Governance objects (in a dedicated GOVERNANCE database for separation of duties)
CREATE TAG governance.tags.data_sensitivity;          -- e.g. PII / PHI / NPI / PCI
CREATE TAG governance.tags.semantic_category;          -- e.g. SSN / VIN / DIAGNOSIS

-- 2. Generic masking policy per data type, bound to the tag
CREATE MASKING POLICY governance.pol.mask_string AS (v string) RETURNS string ->
  CASE WHEN IS_ROLE_IN_SESSION('PII_ALLOWED') THEN v ELSE '***' END;
ALTER TAG governance.tags.data_sensitivity SET MASKING POLICY governance.pol.mask_string;

-- 3. External tokenization policy (partner) bound to a high-sensitivity tag
CREATE MASKING POLICY governance.pol.tok_string AS (v string) RETURNS string ->
  CASE WHEN IS_ROLE_IN_SESSION('DETOKENIZE') THEN partner_detokenize(v) ELSE v END;
ALTER TAG governance.tags.semantic_category SET MASKING POLICY governance.pol.tok_string;

-- 4. Agent applies the tag (protection auto-applies thereafter)
ALTER TABLE claims.raw.fnol MODIFY COLUMN claimant_ssn
  SET TAG governance.tags.data_sensitivity = 'PII',
          governance.tags.semantic_category = 'SSN';

-- 5. Custom classifier for an insurance-specific pattern (VIN)
CREATE OR REPLACE SNOWFLAKE.DATA_PRIVACY.CUSTOM_CLASSIFIER ins_classifiers();
CALL ins_classifiers!ADD_REGEX('VIN','QUASI_IDENTIFIER',
  '^[A-HJ-NPR-Z0-9]{17}$','VIN.*','Vehicle Identification Number',0.8);
```
Map Snowflake system categories to your tags inside the classification profile's `column_tag_map` / `SET_TAG_MAP` so native auto-classification feeds the same tags your agent uses.

#### Sampling strategy (minimize exposure)
- Use `TABLESAMPLE` / `SYSTEM$CLASSIFY` sample of ≤10,000 rows — usually sufficient and the upper bound Snowflake enforces.
- Do value inspection **inside Snowflake's perimeter** (SQL/Snowpark/Cortex) so raw values never leave; pass only **aggregates, hashes, regex match ratios, or masked exemplars** to any external classifier or to a steward UI.
- Prefer metadata-only (column name + type + comment + match statistics) for the LLM step; only send sampled values when metadata is ambiguous, and redact them first (AI_REDACT or Presidio) before they reach any external LLM.

#### Agentic/LLM-specific patterns
- **Keep raw sensitive data in-perimeter.** Prefer Cortex (AI_CLASSIFY/AI_COMPLETE/AI_REDACT) which runs inside Snowflake's security boundary; if you must use an external LLM, send only metadata or redacted samples.
- **Prompt design.** Provide the column name, data type, table/business context, a handful of redacted sample values, and the closed list of your insurance taxonomy categories with short descriptions; request structured JSON output (label + confidence + rationale). Research shows prompt *strategy* matters more than model size, and explicit format/role instructions plus self-augmented structural hints raise structured-table accuracy.
- **Cost control.** Run cheap deterministic layers first; only escalate ambiguous columns to the LLM; batch columns; cache results keyed by (column-name pattern + type + sample signature); use smaller models for the first pass and keep the category list under ~20 per call.
- **Guardrails/validation.** Constrain LLM output to the allowed category set; require a confidence score; never let the LLM directly execute `ALTER`/`GRANT` — it proposes, a deterministic tagger with a least-privilege role applies; log every decision for audit.

#### Evaluation
- Build a **labeled benchmark** from steward-reviewed columns (target a few hundred per category, including hard negatives like premium vs. payout amounts and look-alike codes).
- Measure **per-category precision, recall, F1**: macro-F1 across categories surfaces rare-class weakness; micro-F1 gives overall performance robust to class imbalance. For insurer risk, weight **recall on PHI/SSN/PCI** highly (a missed SSN is worse than a false positive), so consider Fβ with β>1 for those categories.
- Track false-positive rate to control over-masking that breaks analytics. Re-run the benchmark on each model/prompt/regex change and on a schedule to detect drift.

### PART 3 — Insurance-specific classification requirements

**Sensitive data elements in P&C/insurance policyholder data:**
- **Policyholder PII / identifiers:** full name, residential/mailing address, SSN/TIN/ITIN, date of birth, driver's license number, passport, phone, email, online credentials.
- **Financial / NPI:** bank account & routing numbers, payment card data (PAN, expiry, CVV → PCI), premium amounts, payout/settlement/reserve amounts, billing history, credit-based insurance scores.
- **PHI in claims:** medical records, diagnoses and ICD-10 codes, treatment/injury data, provider info, prescriptions — present in health, workers-comp, auto/PIP, and liability bodily-injury claims (these can make portions of a P&C insurer a HIPAA business associate or a hybrid entity).
- **Vehicle/property:** VIN, license plate, telematics, property address, photos/attachments.
- **Beneficiary/third-party:** beneficiary PII, claimant and witness data, and adjuster free-text notes (often the richest and least-structured PII/PHI source — a prime AI_REDACT target).

**Taxonomy design (multi-dimensional).** Model each column on three axes so one classification drives many controls:
1. **Semantic category** (SSN, VIN, DIAGNOSIS, BANK_ACCOUNT, PREMIUM_AMT, BENEFICIARY_NAME…).
2. **Sensitivity tier / privacy category** (IDENTIFIER, QUASI_IDENTIFIER, SENSITIVE — reuse Snowflake's privacy categories).
3. **Regulatory class** (NPI-GLBA, PHI-HIPAA, PCI, CCPA-PI, GDPR-special-category).

Encode insurance specifics as **custom classifiers** (policy number, claim number, NAIC company code, VIN, ICD-10) and map system semantic categories into these tags via the classification profile. Keep governance tags/policies in a dedicated governance database for separation of duties (custom roles such as TAG_ADMIN, MASKING_ADMIN, CLASSIFICATION_ADMIN).

### PART 4 — Compliance mapping

| Category (tag) | Primary regimes | Controls the tag should trigger |
|---|---|---|
| SSN/TIN, driver's license, passport | GLBA, NAIC/NY DFS, CCPA, state breach laws | Tokenize or strong mask; restrict roles; encryption at rest/in transit; breach-scope flag |
| Bank/account, payment card (PAN/CVV) | GLBA, **PCI DSS** | Tokenize (PCI scope reduction); never store CVV; strict RBAC; audit |
| PHI / diagnosis / ICD-10 / injury | **HIPAA**, GLBA, state | Mask/limit to minimum-necessary roles; row access for treating/handling staff; audit + de-identification for analytics |
| Premium/payout/financial NPI | GLBA, NAIC/NY DFS | Role-based masking; access logging |
| Name/address/DOB/phone/email (PII/QI) | GLBA, CCPA/CPRA, GDPR | Mask for unauthorized roles; support DSAR/erasure via inventory; retention tagging |
| VIN/vehicle/telematics, beneficiary | CCPA, GLBA | Quasi-identifier handling; combine-risk review |

**How tagging supports each obligation.**
- **GLBA Safeguards Rule (FTC amendment, compliance deadline June 9, 2023; breach-notification amendment effective May 13, 2024 for incidents affecting 500+ consumers, reportable within 30 days):** requires a written risk assessment and inventory of customer information, encryption of customer information at rest and in transit, and access controls. Tags = the live inventory of Nonpublic Personal Information (NPI); tag-based masking/tokenization + RBAC = the access/encryption controls; classification reports = evidence. For insurers, GLBA is enforced state-by-state via state adoptions of the NAIC Privacy of Consumer Financial and Health Information Regulation (Model #672); all 50 states have adopted some version.
- **NAIC Insurance Data Security Model Law (Model #668, adopted 2017) & NY DFS 23 NYCRR 500:** Section 500.03 lists required cybersecurity-policy areas verbatim including "(b) data governance and classification" (the November 2023 amendments, effective April 29, 2024, add "and retention"); Section 500.15 requires encryption of Nonpublic Information at rest and in transit. Classification tags + retention tags directly evidence both. 23 NYCRR 500 also drives 72-hour Cybersecurity-Incident reporting — tags let you scope which Nonpublic Information was in an affected table. (Note: Model #668 is the data-security law; Model #672 is the distinct GLBA-implementing privacy regulation — don't conflate them in your control mapping.)
- **HIPAA:** PHI tags drive minimum-necessary access (row/column policies), encryption, and de-identification (strip the 18 identifiers) for analytics; audit logs of access to PHI-tagged columns provide accountability.
- **PCI DSS:** PAN/CVV tags drive tokenization/external tokenization to keep cardholder data out of analytic scope; CVV must never be stored.
- **CCPA/CPRA & state privacy laws:** PII tags power data-subject access/deletion requests by giving an authoritative map of where a consumer's personal information lives; many insurers are partly exempt via GLBA entity/data exemptions but still need the inventory.
- **GDPR (where applicable):** special-category (health) tags drive Article 9 protections and DPIAs.

**Practical control-triggering rule of thumb:** IDENTIFIER + (GLBA|HIPAA|PCI) → tokenize or strong-mask + restrict + audit; QUASI_IDENTIFIER → role-based mask + combine-risk review; SENSITIVE (health/financial) → minimum-necessary access + row policy + de-identify for analytics. Retention tags drive automated deletion to satisfy data-minimization and retention requirements.

## Recommendations

**Stage 0 — Foundations (week 1–2).** Confirm Enterprise Edition + Cortex enablement (grant CORTEX_USER). Stand up a dedicated `GOVERNANCE` database with custom roles (TAG_ADMIN, MASKING_ADMIN, CLASSIFICATION_ADMIN) for separation of duties. Define the insurance taxonomy (semantic × sensitivity × regulatory) and create the tags and generic per-data-type masking policies bound to those tags.

**Stage 1 — Native baseline (week 3–4).** Turn on automatic classification with a classification profile at the database level on your raw/landing databases; configure `column_tag_map` to translate native semantic categories into your tags. Add custom classifiers for insurance specifics (policy/claim number, VIN, ICD-10, NAIC code). Validate against a small labeled set. This alone gives you continuous discovery + auto-tagging + auto-masking with minimal code.

**Stage 2 — Agentic enrichment (month 2).** Build the event-driven scanner (streams + triggered tasks for data arrival, plus ACCOUNT_USAGE/INFORMATION_SCHEMA polling with a watermark for new tables) and a classifier procedure that runs the ensemble: heuristics → custom classifiers/regex → sampled-value stats → Cortex AI_CLASSIFY tie-breaker (metadata-only or AI_REDACT-scrubbed samples). Auto-tag at ≥0.9 confidence; route 0.6–0.9 to a Streamlit steward review app; log <0.6. Add AI_REDACT over free-text claims/adjuster-note columns.

**Stage 3 — Downstream protection & evidence (month 2–3).** For PAN/SSN/bank tags, integrate one external-tokenization partner (Protegrity/ALTR/Skyflow/Thales) and bind the tokenization policy to the high-sensitivity tag. Wire row access policies (mapping-table based) for claims data so adjusters see only their book. Build a compliance dashboard from `TAG_REFERENCES`, `POLICY_REFERENCES`, `DATA_CLASSIFICATION_LATEST`, and `ACCESS_HISTORY` as audit evidence for GLBA/NAIC/NY DFS exams.

**Stage 4 — Evaluate & iterate (ongoing).** Maintain the labeled benchmark; report per-category precision/recall/F1 monthly; tune thresholds and regex; feed steward corrections back as LLM few-shot examples. Re-validate classifications before `maximum_classification_validity_days` expiry.

**Decision thresholds that change the plan.**
- If your sensitive data extends materially beyond Snowflake (S3 claims documents, email, SaaS), add a DSPM (Cyera/Sentra/BigID) rather than over-extend the native agent.
- If recall on PHI/SSN/PCI in your benchmark falls below ~0.95, strengthen the value-inspection and LLM layers before trusting auto-masking.
- If LLM token cost per scan exceeds the credit cost of native classification by a wide margin, restrict the LLM to ambiguous columns only.
- If you must satisfy PCI audit scope reduction, tokenization (not masking) is mandatory for PAN.

## Caveats
- **Snowflake costs are referenced, not fixed.** Sensitive data classification consumes serverless credits under SERVICE_TYPE `SENSITIVE_DATA_CLASSIFICATION` (queryable in METERING_HISTORY / METERING_DAILY_HISTORY, and in Snowsight Cost Management); the per-credit rate points to Table 5 of Snowflake's Service Consumption Table rather than a single published prose number. Cost scales with **column count** and rises sharply for **views** (off by default). Model your own spend before enabling account-wide.
- **The "more than 150 categories" figure** is from a Snowflake engineering blog ("Cortex Code Governance Skills"); the canonical native-category documentation page does not state an exact count. AI_REDACT's official docs enumerate **12 named categories** (with sub-types); a "50+ PII types" claim appears in a Snowflake Labs lab repo but the docs table is authoritative. AI_REDACT's precise GA month (late 2025) is cited by a third party, not directly verified against a Snowflake release note.
- **LLM accuracy on structured data is limited** (65.43% in Microsoft's WSDM '24 SUC benchmark with optimal prompting) — do not make the LLM the sole or primary classifier, and never let it execute DDL/grants directly.
- **State-by-state variation is real.** GLBA for insurers is implemented via state adoptions of NAIC models with uneven currency; NY DFS Class A vs. smaller-entity obligations differ; confirm your specific state adoptions and any HIPAA business-associate/hybrid-entity status with counsel. Compliance mappings here are operational guidance, not legal advice.
- **Tag latency & limits.** ACCOUNT_USAGE views and Snowsight Tags/policies dashboards have latency (Tagged Objects up to ~2 hours, Dashboard updates ~every 12 hours); auto-classification starts ~1 hour after profile set; classification profiles have object-count limits (not directly on >10,000 schemas; tables with >10,000 columns can't be auto-classified). Design the agent to tolerate these.
- **Over-masking risk.** Aggressive auto-tagging can break analytics/joins; keep the human-in-the-loop band and a fast un-tag path, and prefer conditional/role-based masking that preserves analytic utility where lawful.