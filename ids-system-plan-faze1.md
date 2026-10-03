# IDS — Phase 1 Architecture Plan and Session Handoff

Created: 2 October 2026  
Last edited and files checked: 4 October 2026  
Product development root: `/home/esip/Documents/ids-system`  
ML experiments and model root: `/home/esip/Documents/ids-model`  
Document role: Primary reference for current architecture decisions, implementation status, and open questions.

**Reading rule:** An approved architecture decision does not mean a feature has been implemented or its effectiveness verified. This document distinguishes decisions from evidence. Approval to edit this document does not approve any open architecture proposals.

## Contents

1. [Starting summary for a new session](#baslangic)
2. [Verified existing work](#mevcut)
3. [Product goals and scope boundaries](#kapsam)
4. [Architecture, responsibilities, and data flow](#mimari)
5. [Approved decisions — M01–M20](#kararlar)
6. [Open decisions — A01–A11](#acik)
7. [Proposed starting decisions for the first engine](#ilk-motor)
8. [Session handoff and working rules](#devir)
9. [Source guide and historical documents](#kaynaklar)
10. [Glossary](#sozluk)
11. [Document validation and update history](#kontrol)

<a id="baslangic"></a>
## 1. Starting summary for a new session

| Topic | Current status |
| --- | --- |
| Goal | A general-purpose, open-source HTTP IDS that is useful in practice and customizable through application profiles |
| Phase 1 | Detect SQLi, XSS carried in HTTP requests, and path traversal attempts; no automatic blocking |
| Product architecture | Go core; ML development in Python; integration with an existing TLS reverse proxy; rule, ML, and application-profile layers |
| Rule engine | Our own Go SecLang engine; CRS 4.30.0; initially PL1 within the selected attack groups |
| Existing implementation | Python data preparation and feature extraction, a trained Random Forest pilot, and test reports |
| Not yet implemented | Go product engine, live proxy integration, product profile/decision/logging infrastructure, and a verified ONNX migration |
| Approved decision count | M01–M20: 20 decisions; implementation status is tracked separately |
| Open topics | A01–A11: 11 main topics, each potentially containing multiple subdecisions |
| Next discussion | M21 proposal: prepare rules at startup and keep each request's execution state separate; not yet approved |

**For the next agent:** First verify the current status in this document against the relevant files. Then discuss the first open decision in section 7 with the user. The user wants numbered discussions, one decision at a time; do not finalize other proposals or begin application implementation without approval.

### 1.1. Meaning of status labels

| Label | Meaning |
| --- | --- |
| Approved | The user accepted the architectural choice; this does not establish that the code exists |
| Existing / implemented | The relevant file or code exists; its scope is supported by a source |
| Verified | Evidence exists for the stated check; verification applies only to that scope |
| Proposal / open | Undecided; a new agent must not silently treat it as the default choice |
| Deferred | Outside the initial scope; future details and completion dates are not settled |
| Historical / superseded | Describes an earlier stage; not the current status or technology choice |

<a id="mevcut"></a>
## 2. Verified existing work

This section is based on reading existing files. While editing this document, we did not load or run the model, retrain it, or rerun application tests.

| Work | Status verified from files | Evidence |
| --- | --- | --- |
| Data | 1,000 HTTP records selected from CSIC 2010; 604 training, 197 validation, 199 test records | [Split record](../ids-model/data/processed/http-mini-splits-v1/split_report.json) |
| Split policy | Content grouping; the old endpoint grouping is not used in the main experiment | [Data split report](../ids-model/reports/http-veri-ayrimi.md) |
| Features | 16 basic + 5 pattern features extracted in Python, 21 in total; source metadata is not model input | [Extractor](../ids-model/scripts/extract_features.py), [feature report](../ids-model/reports/oznitelik-cikarici.md) |
| Preprocessing | Constant-feature selection fitted only on training data; 18 of 21 features retained; invalid numeric values rejected; no scaling | [Training record](../ids-model/models/rf-baseline-v1/run.json) |
| Model | A pipeline containing preprocessing and the trained Random Forest exists | [Model file](../ids-model/models/rf-baseline-v1/pipeline.joblib), [training code](../ids-model/scripts/train_random_forest.py) |
| Validation | F1 72.53%; false positive rate 18.18% on 197 records | [Training record](../ids-model/models/rf-baseline-v1/run.json) |
| Test | Fixed model evaluated on 199 records; F1 66.32%; false positive rate 28.00%; no retraining | [Test record](../ids-model/reports/rf-baseline-v1-test/test_report.json) |
| Go product | No Go module/product engine in the inspected directories; architecture decisions are not implementation evidence | [Project summary](../ids-model/README.md), project file inventory |
| CRS | Version 4.30.0 sources are available locally; downloading and inspecting them does not establish engine support | [CRS source directory](coreruleset-4.30.0) |
| Rule demos | The 930110 and PL1/PL2 execution-order explanations are educational, not full engine tests | [930110 demo](reports/crs-930110-kural-demosu.md), [PL demo](reports/crs-pl1-pl2-calisma-sirasi.md) |

### 2.1. Pilot experiment: technical summary and limitations

1. Random Forest: 100 trees, maximum depth 10, minimum 5 samples per leaf, `random_state=42`, and `n_jobs=2` during training. Decision rule: `score > 0.5`; a tie predicts normal. The score is not presented as a calibrated attack probability.
2. The training-constant features `duplicate_param_count`, `control_char_count`, and `path_traversal_count` were removed. This is not a decision to exclude these features or their associated attacks from the product permanently.
3. Validation: TN=81, FP=18, FN=32, TP=66. Test: TN=72, FP=28, FN=36, TP=63. These are pilot results, not evidence of product effectiveness on real traffic.
4. The dataset is old, synthetic, and small, intended for practice. Content grouping helps keep similar records together; it does not guarantee the absence of all leakage or true session independence. The source label `anomalous` does not mean every record is a confirmed attack.
5. The test set has now been observed. We will not tune against these results and present the same set as an unseen final test. A07 will define a new unbiased evaluation setup.
6. The existing Python extractor's body parsing is limited to form-urlencoded content. The broader product scope in M17, including JSON and multipart, is neither implemented nor validated for the existing model.
7. The pilot has not been selected as the final product model. The Go feature extractor and ONNX migration have not been implemented.

**Historical record differences:** `model_trained: false` in the split report and `test_evaluated: false` in the training record describe the stages when those records were produced. The later training and test report dated 27 September 2026 complete the current picture. These historical records are not retroactively rewritten.

<a id="kapsam"></a>
## 3. Product goals and scope boundaries

### 3.1. Approved product goals

1. **Product goal:** Build a useful, open-source IDS, initially focused on HTTP and extensible to other protocols later.

2. **Detection first, prevention later:** Phase 1 inspects requests and produces alerts; it does not automatically block requests. Prevention is a later stage once detection quality is adequate. Transition criteria have not been defined.

3. **General usability:** The core will not be tied to one web application. It should support different applications, with application-specific settings where necessary. Equal effectiveness across every application is not guaranteed.

4. **Initial detection scope:**
   - SQL injection (SQLi) attempts.
   - Cross-site scripting (XSS) attempts carried in HTTP requests.
   - Path traversal attempts to access locations outside an allowed file path.

   This does not claim detection of every SQLi/XSS variant or coverage of the entire OWASP Top 10. The initial goal is to detect attack attempts, not automatically prove the existence of a vulnerability or the success of an attack.

5. **Later stages:** Checks for behavior over time, such as repeated login attempts, and automatic prevention are outside the initial detection scope.

6. **Multiple detection layers:** ML is one part of the system. Success will be assessed through the detection and false positive results of the whole system, not only an ML score. M04 approves separate findings from each layer. M10 approves combining layer scores through a decision mechanism. Detailed responsibilities and the combination method remain open.

### 3.2. Three distinct completion levels

| Level | Goal | Status and boundary |
| --- | --- | --- |
| First working rule engine | An initial engine that accepts offline HTTP examples and executes selected real CRS rules | Proposed first development step; exact rules, input/output, and acceptance criteria remain open. This is not all of Phase 1 or all PL1 rules |
| Phase 1 product | TLS/proxy integration, HTTP analysis, rule/ML/profile layers, decisions, and protected records/alerts | Architectural boundaries M01–M20 are approved; technical details remain open in A01–A11 |
| Later stages | Prevention, PL2–PL4, broader CRS support, traffic-based profile learning, and other protocols | Not completed work or scheduled first-release commitments; prevention transition criteria will be chosen separately |

### 3.3. Interpreting HTTP scope

**Status: General goal accepted; initial content scope approved in M17.**

Broad support for different HTTP request structures is a goal. M17 defines the content types and body formats for the initial release. Detailed method behavior, HTTP versions, size limits, and parsing details will be decided separately. The proxy's ability to forward a request and the IDS's ability to analyze its content will be assessed separately. This goal does not imply that all HTTP content is already supported.

The complete content-type table is in [M17](#m17): form-urlencoded, nested JSON, multipart text fields/file names/metadata, and plain text are within the initial product scope. Multipart file contents, structured XML, compressed-body decompression, WebSocket messages, and response bodies are deferred. The first engine's narrower starting scope will be chosen separately and must not be presented as implementing the full product scope.

<a id="mimari"></a>
## 4. Architecture, responsibilities, and data flow

This diagram shows approved responsibilities. It does not select a proxy product, transfer protocol, queue, service boundaries, or parallel execution strategy.

```text
Client --HTTPS--> Existing reverse proxy --HTTP/HTTPS--> Protected application
                         |
                         +-- request copy --+  (application does not wait for IDS)
                                            |
Offline HTTP source ----> input adapter ----+
                                            v
                                Shared HTTP information groups
                           received content / parsed view / analysis status
                                            |
                          +-----------------+-----------------+
                          v                 v                 v
                      Rule engine      Go features      Application-profile
                      SecLang/CRS    + ONNX inference        checks
                          |                 |                 |
                          +-------- separate findings/scores -+
                                            v
                                    Decision mechanism
                                            v
                                 Recording policy / masking
                                            v
                                    Record and any alert
```

The detailed TLS policy for the proxy-to-application connection remains open in A01. Drawing layers side by side does not approve parallel execution. Incomplete-analysis information is preserved throughout the flow; it is not an attack indication on its own.

| Component | Responsibility | Open implementation details |
| --- | --- | --- |
| Existing reverse proxy | Terminate TLS for the protected domain, forward the request, and supply a copy | Product, transfer, and buffering behavior — A01 |
| Go ingestion/analysis management | Connect source data to the common HTTP analysis flow | API, queue, workers, and resource limits — A01/A02/A08 |
| Go HTTP representations | Preserve received content, parse supported formats, and carry analysis status | Data types, parsers, and encoding — A02 |
| Go rule engine | Execute SecLang behavior required by selected CRS rules | Exact list, operators/transformations, and libraries — A11 |
| Go feature extraction and model invocation | Produce the same numeric inputs used in training and invoke ONNX inference | Feature contract and conversion compatibility — A10 |
| Python ML development | Training, evaluation, and portable-model preparation | New model/data and success criteria — A05/A07/A10 |
| Profile layer | Check manually defined application expectations | Profile format and checks — A04 |
| Decision mechanism | Produce alert decisions from separate layer results | Scoring policy, thresholds, and missing results — A03/A06 |
| Recording and presentation | Present findings/decisions while protecting sensitive content | Storage, API/dashboard, access, and retention — A03/A09 |

**Data invariants:** The parsed view does not replace received content; repeated values are preserved. Rule-specific transformations do not alter shared input. CRS per-request variables/scores are handled separately. M21 proposes translating this principle into engine startup and request execution behavior; it is not yet approved. Analysis may use actual sensitive values; persistent records follow M11.

<a id="kararlar"></a>
## 5. Approved decisions — M01–M20

The following index is for navigation. The detailed rationale, examples, and boundaries are preserved. Each decision's implementation status is tracked separately from its approval.

| Decision | Topic | Open topics |
| --- | --- | --- |
| [M01](#m01) | Separate ingestion from analysis | A01, A02, A03 |
| [M02](#m02) | HTTPS and an existing reverse proxy | A01, A08, A09 |
| [M03](#m03) | Common HTTP request format | A02, A03 |
| [M04](#m04) | Separate findings from each layer | A03, A06 |
| [M05](#m05) | Visibility of incomplete analysis | A02, A03, A08 |
| [M06](#m06) | Separate application-specific settings | A04, A06, A09 |
| [M07](#m07) | Manually defined profiles | A04, A09 |
| [M08](#m08) | Extensibility to other protocols | A02, A03 |
| [M09](#m09) | Fast analysis of request copies | A01, A08 |
| [M10](#m10) | Decisions based on layer scores | A03, A06, A07 |
| [M11](#m11) | Separate sensitive-data analysis from recording | A04, A09 |
| [M12](#m12) | Go and Python responsibilities | A01, A08, A10, A11 |
| [M13](#m13) | Shared Go feature extractor | A02, A07, A10 |
| [M14](#m14) | Use models from Go through ONNX | A08, A10 |
| [M15](#m15) | Our own CRS/SecLang engine | A02, A03, A11 |
| [M16](#m16) | Three HTTP information groups | A02, A03 |
| [M17](#m17) | Phase 1 HTTP content scope | A02, A08, A11 |
| [M18](#m18) | Pin CRS to version 4.30.0 | A11 |
| [M19](#m19) | SQLi, XSS, and path traversal groups | A11 |
| [M20](#m20) | Initially PL1 | A11 |

<a id="m01"></a>
### 5.1. M01 — Architectural principle

**Implementation / verification status:** The product engine is not implemented.

**Scope and open boundaries:** Offline and live inputs will connect to a common engine; adapter APIs remain open.

**Related decisions:** M02, M03, M16. **Open detail records:** A01, A02, A03.

**Status: Approved.**

**Decision:** Separate the component that brings HTTP requests into the system from the detection engine that analyzes them.

A request read from a file and one received from a live application should enter the same detection engine after conversion to the common request format we will define.

**Rationale:** Avoid rewriting detection logic when the ingestion method changes, and allow the same engine to be tested with offline experiments and live traffic.

M01 separates ingestion and analysis responsibilities. M02 approves using a reverse proxy for Phase 1 live-traffic integration. M03 approves the common request format's basic fields; M05 approves the principle for reporting incomplete analysis.

<a id="m02"></a>
### 5.2. M02 — HTTPS support and proxy

**Implementation / verification status:** Live proxy/TLS integration is not implemented.

**Scope and open boundaries:** TLS termination for an authorized domain; proxy product, transfer, and setup remain open.

**Related decisions:** M01, M09. **Open detail records:** A01, A08, A09.

**Status: Approved.**

**Accepted requirement:** The product must be able to inspect HTTPS request content. The proxy is responsible for terminating TLS; the detection engine analyzes the HTTP request passed to it.

**Decision:** Phase 1 will include integration with a TLS-terminating reverse proxy. The detection engine will analyze HTTP requests received through the proxy. We will integrate an existing proxy; the product and detailed setup will be chosen separately.

General flow of this decision (HTTPS is shown for the application connection):

```text
Client --HTTPS--> Reverse proxy --HTTPS--> Web application
                       |
                       +-- HTTP request copy --> IDS --> Alert
```

The proxy handles the client's TLS connection using the protected domain's certificate and private key. It can pass that connection's HTTP content to the IDS. A separate HTTPS connection may be established between the proxy and the web application. This does not mean decrypting arbitrary encrypted packets captured from the network.

TLS support belongs to the ingestion layer; it is not a prevention feature. In Phase 1, IDS findings lead to alerts, not automatic blocking based on an attack decision. M03 defines the basic request fields. Under M09, requests reach the application without waiting for IDS analysis to finish; the IDS works on a copy. The copy transfer mechanism and processing limits will be decided separately.

Rationale: An HTTP IDS that cannot see HTTPS content cannot perform content-based checks such as SQLi/XSS inspection on that traffic. TLS integration is a basic requirement for live use.

Technical reference: [NGINX — SSL Termination](https://docs.nginx.com/nginx/admin-guide/security-controls/terminating-ssl-http/).

<a id="m03"></a>
### 5.3. M03 — Common request format

**Implementation / verification status:** The product data contract is not implemented.

**Scope and open boundaries:** Basic fields are defined; Go data types and the access contract remain open.

**Related decisions:** M05, M08, M16, M17. **Open detail records:** A02, A03.

**Status: Approved.**

**Decision:** HTTP requests from files and the proxy will be converted into the same common request format before entering the detection engine.

Basic fields:

1. HTTP method (for example, GET or POST).
2. Request path (for example, /arama).
3. Query parameters (for example, q=kitap).
4. HTTP headers.
5. Request body.

**Rationale:** Let the detection engine use the same analysis flow regardless of the request's source, and test the same engine with offline data and live traffic.

This common format is for HTTP requests. Other protocols added later under M08 may use their own data formats.

This format is not the feature list passed directly to the ML model. Model inputs will be defined separately; source metadata will not be included in model input.

Analysis that cannot be completed because content is incomplete or unreadable will be reported under M05. M16 approves separating received content, parsed views, and analysis status, and preserving repeated values. M17 approves the initial release's content scope. Technical field types, detailed representations, and processing limits remain undecided.

<a id="m04"></a>
### 5.4. M04 — Separate findings from each layer

**Implementation / verification status:** Product layers and the common finding contract are not implemented.

**Scope and open boundaries:** Rules, ML, and profiles produce separate results; the result schema remains open.

**Related decisions:** M05, M10, M11. **Open detail records:** A03, A06.

**Status: Approved.**

**Decision:** The rule layer, ML layer, and application-structure checking layer will produce separate findings. Under M10, a decision mechanism using layer scores will turn findings into alerts; its calculation method will be defined separately.

Example findings:

1. Rule layer: A particular attack pattern was found in the request.
2. ML layer: A model score was produced for the request.
3. Application check: A parameter does not match its expected structure.

**Rationale:** Make it possible to inspect which layer contributed to an alert and where a false positive originated, and evaluate each layer's results separately.

This decision does not mean every individual finding must generate an alert. The common output format, interpretation of model scores, thresholds, and combination method remain undecided.

<a id="m05"></a>
### 5.5. M05 — Explicitly report incomplete analysis

**Implementation / verification status:** Not implemented or verified across the product.

**Scope and open boundaries:** Empty content is distinct from uninspectable content; status and error formats remain open.

**Related decisions:** M03, M09, M16, M17. **Open detail records:** A02, A03, A08.

**Status: Approved.**

**Decision:** Requests that cannot be inspected, or are only partly inspected, will not be treated as normal as if analysis were complete. The result will indicate incomplete analysis.

For example, an unreadable request body or an unsupported content type that prevents inspection will be reported. A genuinely bodyless request is not incomplete merely because it has no body.

**Rationale:** Distinguish “we inspected it and found no attack” from “we could not inspect it,” and make traffic outside the system's visibility apparent.

Incomplete-analysis information alone does not mean an attack alert or blocking. Findings from inspectable sections are preserved separately. The technical status fields and presentation of incomplete-analysis information will be defined later.

<a id="m06"></a>
### 5.6. M06 — Separate application-specific settings

**Implementation / verification status:** Profile infrastructure is not implemented.

**Scope and open boundaries:** The general core and application settings are separate; profile selection and effects remain open.

**Related decisions:** M07, M10, M11. **Open detail records:** A04, A06, A09.

**Status: Approved.**

**Decision:** Application-specific settings will remain separate from the general IDS core. The same core can serve different applications with their own settings. A setting for one application will not change checks for other applications.

For example, an application's acceptance of HTML at /yorum may be expressed in its profile. This setting will not carry over to other applications; allowing HTML does not by itself exempt that field from every attack check.

**Rationale:** Keep a common detection engine while handling applications' different request structures and needs separately.

M07 approves manually defined profiles for Phase 1. The profile format and the effects of settings on alert decisions remain undecided.

<a id="m07"></a>
### 5.7. M07 — Initially use manually defined application profiles

**Implementation / verification status:** Profile loading and validation are not implemented.

**Scope and open boundaries:** Automatic learning from traffic is deferred; the file/interface format remains open.

**Related decisions:** M06, M11. **Open detail records:** A04, A09.

**Status: Approved.**

**Decision:** Phase 1 will allow manually defined profiles describing an application's expected request structure. Automatic profile learning from traffic is deferred to later stages.

For example, the profile may express that the q parameter at /arama is expected to contain text.

**Rationale:** Make it clear why each expectation is used in the initial stage and simplify investigation of false positives.

The profile-definition interface or file format has not been selected. This decision does not define the ML model's training method; it concerns how application expectations are specified.

<a id="m08"></a>
### 5.8. M08 — Extensibility of HTTP scope and support for other protocols

**Implementation / verification status:** Product components are not implemented.

**Scope and open boundaries:** Phase 1 is HTTP-focused; integration interfaces for new protocol components remain open.

**Related decisions:** M01, M03, M17. **Open detail records:** A02, A03.

**Status: Approved.**

**Decision:** Phase 1 will remain HTTP-focused. The architecture will allow broader HTTP support and components for different protocols in the future.

HTTP-specific ingestion, parsing, and analysis will live in distinct components. Shared parts that coordinate analysis and process findings will not assume every protocol has fields such as an HTTP method or path. M03's request format will be the common format for HTTP components; new protocols may introduce their own data formats and analysis components.

**Rationale:** Reduce the need to rewrite the existing system when adding a protocol or HTTP capability.

New protocols' ingestion methods, checks, and any ML models will be designed and evaluated separately. A model trained for HTTP will not be assumed to work directly with other protocols.

No new protocol support will be implemented at this stage. Which protocols to add and how components connect technically will be decided later.

<a id="m09"></a>
### 5.9. M09 — Analyze copies and produce decisions quickly

**Implementation / verification status:** The live flow and performance measurements have not been implemented/performed.

**Scope and open boundaries:** The application does not wait for analysis decisions; numeric targets and overload behavior remain open.

**Related decisions:** M02, M05, M10. **Open detail records:** A01, A08.

**Status: Approved.**

**Decision:** In Phase 1, requests will reach the application without waiting for IDS analysis to finish. The IDS will analyze a supplied copy, producing a decision and, where appropriate, an alert.

**Performance requirement:** Even though analysis does not hold up the application, decisions and alerts must be produced quickly. Technology and architecture choices must account for analysis falling behind and alerts being delayed as traffic increases.

The proxy, copy transfer, parsing, rule checks, ML inference, and finding-combination mechanism will be assessed against this requirement. Performance will not be evaluated only through ML inference time.

Measurements to consider:

1. Time from the proxy receiving the request to the analysis decision and any alert, including transfer and any queue wait.
2. Slow-request latency in addition to the average; for example, the time within which 95% of requests complete (p95).
3. Requests analyzed per second and work accumulating under heavy traffic.
4. The proxy/copying overhead added to the protected application's response time, plus CPU and memory consumption.

**Rationale:** Avoid making the application wait for IDS decisions while producing detections early enough to be useful.

Numeric latency and capacity targets will be decided after selecting target hardware, traffic intensity, and request sizes. Technology choices will be supported by measurements under those conditions. Overload behavior, queue limits, and reporting of unanalyzed copies will be discussed separately; M05's incomplete-analysis principle will be preserved.

This decision applies to Phase 1 detection. Request waiting and blocking behavior will be reconsidered when moving to prevention.

<a id="m10"></a>
### 5.10. M10 — Decision mechanism based on layer scores

**Implementation / verification status:** The decision mechanism is not implemented.

**Scope and open boundaries:** Scores are evaluated together; scales, weights, and thresholds remain open.

**Related decisions:** M04, M05, M11. **Open detail records:** A03, A06, A07.

**Status: Approved.**

**Decision:** The decision mechanism will evaluate scores from all detection layers to produce alert decisions. Separate layer findings will be preserved under M04. The mechanism will meet M09's requirement for fast decision generation.

**Rationale:** Evaluate the results of rules, ML, and application checks together in the system's overall alert decision.

The meanings, scales, comparison method, weights, and alert thresholds for layer scores have not been chosen. Directly averaging scores has not been approved. The same numeric value may not represent the same confidence or attack probability across layers. Layers that cannot produce a score or complete inspection will be handled consistently with M05; missing results will not be interpreted as normal results.

<a id="m11"></a>
### 5.11. M11 — Separate sensitive-data analysis from recording

**Implementation / verification status:** Product logging/masking infrastructure is not implemented.

**Scope and open boundaries:** Actual values are analyzed; persistent records are protected; technical policy remains open.

**Related decisions:** M06, M07, M16. **Open detail records:** A04, A09.

**Status: Approved.**

**Decision:** The IDS will inspect the actual values of fields needed for analysis. Sensitive values will be masked or omitted when written to persistent records such as logs, alerts, and reports. Masking for recording will not alter the request delivered to the protected application.

Sensitive fields will not be exempt from security checks. For example, suspected SQLi in a password field can be evaluated using its actual value, while the record contains the field location, finding, and score but hides the password. Matched text snippets and error descriptions follow the same recording policy.

Common retention defaults will be supplemented by application-specific sensitive-field definitions. We will not rely only on detecting names such as password. Profiles may specify method, request path, and field location; for example, credentials.secret in the JSON body of POST /giris may be defined as sensitive.

Complete raw requests and all field values will not be recorded by default. Records will be limited to information explaining the analysis result, such as findings, scores, and field locations. Where content recording is necessary, recordable fields will be defined separately. This avoids automatically recording sensitive fields that have not been explicitly identified.

**Rationale:** Inspect sensitive content for attack detection without exposing it in persistent records.

The full field list, technical profile format, retention periods, and record access permissions will be decided separately. This is an architectural decision, not evidence that masking has been implemented.

<a id="m12"></a>
### 5.12. M12 — Go and Python responsibilities

**Implementation / verification status:** The Python pilot exists; the Go product core does not yet exist.

**Scope and open boundaries:** Go for the live core, Python for ML development; other product technologies remain open.

**Related decisions:** M13, M14, M15. **Open detail records:** A01, A08, A10, A11.

**Status: Approved; the application has not yet been developed.**

**Decision:** The live IDS core will be developed in Go. Python will be used for model training, evaluation, and deployment preparation. Live inference is not intended to depend on a separate Python service; the model will run through an inference runtime invoked by the Go application.

| Component | Responsibility |
| --- | --- |
| Go — data processing | Accept request copies, manage the work queue, parse HTTP, and construct the common request format |
| Go — feature extraction | Calculate the numeric features expected by the model |
| Go — detection layers | Implement our CRS-supporting rule engine, application-profile checks, and model invocation |
| Go — decisions and presentation | Combine layer findings, mask sensitive data, record alerts, and provide the management API |
| Python — ML development | Prepare training/evaluation data, train and evaluate models, and convert them into portable model files |
| Existing reverse proxy | Terminate TLS and transfer request copies under M02; proxy product not yet selected |

**Rationale:** Keep traffic processing and decision flow in Go, use Python's ML development tools, and reduce the need to transfer data between services for live inference.

M15 approves developing our own CRS-supporting Go rule engine, superseding the earlier candidacy of Coraza as the product engine. Coraza and CrowdSec architectures may be studied for learning and comparison. This decision does not select a dashboard technology, storage product, or decision-calculation method.

This language split alone does not guarantee speed. End-to-end time, including feature extraction and inference, will be measured under M09. Requests delivered to the application will not wait for IDS results; delayed or incomplete analysis under load will be visible under M05.

<a id="m13"></a>
### 5.13. M13 — Shared feature extraction for training and live use

**Implementation / verification status:** The current extractor is Python; migration to Go has not happened.

**Scope and open boundaries:** Training and live calculations will be identical; feature contract and version remain open.

**Related decisions:** M03, M12, M14, M16. **Open detail records:** A02, A07, A10.

**Status: Approved; migration from the existing Python pilot has not yet happened.**

**Decision:** Product feature extraction will be developed in Go. The same Go extractor will produce numeric tables from training data and convert live requests into model inputs. Python will train the model using that table; the same feature calculations will not be separately reimplemented in Python.

**Rationale:** Prevent discrepancies between training and live calculations. Feature names, ordering, types, byte/character length semantics, URL decoding, and repeated-parameter handling will be explicit. The feature-definition version will be tracked with the model. Source metadata will not be included in model input.

Feature extraction and model preprocessing are separate steps. Operations in the current pilot, such as retaining 18 of 21 features and checking invalid numeric values, will be preserved during model migration. Compatibility investigation will determine whether they run inside ONNX or on the Go side. Feature selection will not be relearned during live use; the selection fitted during training will be reused.

During migration to Go, features from the same requests will be compared with the existing Python calculations. Any intentional feature change will be treated as a new version with appropriate training/evaluation. Recording this decision has not changed the pilot code, model, or data split.

<a id="m14"></a>
### 5.14. M14 — Run the model from Go

**Implementation / verification status:** Architectural direction approved; candidate binding and pipeline conversion not verified.

**Scope and open boundaries:** ONNX Runtime is the chosen direction; yalue/onnxruntime_go is not a finalized dependency.

**Related decisions:** M12, M13. **Open detail records:** A08, A10.

**Status: Architectural direction approved; candidate library and existing pipeline compatibility not yet verified.**

**Decision:** Aim to convert the Python-trained model into ONNX and execute it through ONNX Runtime from the Go application. The concrete Go binding candidate is `github.com/yalue/onnxruntime_go`. A separate Python inference service will not be the default architecture.

```text
Training: Data → Go feature extractor → Numeric table → Python training → ONNX model
Live:     Request copy → Go feature extractor → ONNX Runtime → ML score
                                                                 ↓
                                             Go: combine layers → Decision → Alert
```

ONNX is a model file format; ONNX Runtime performs computation; `onnxruntime_go` allows Go code to call that runtime. This community library requires `cgo` and a suitable ONNX Runtime shared library. Removing Python from live inference does not mean deployment is a single Go file without additional libraries. The model will be loaded at startup and reused, not reloaded or trained for every request.

**Migration condition:** ONNX converter support exists for Random Forest, but Go will not directly open the current `pipeline.joblib`. Conversion compatibility, including custom preprocessing, input/output format, feature order, class mapping, and decision threshold, must be verified. Python and converted-model scores will be compared on identical inputs for numeric differences, with decisions checked especially around the threshold. This comparison will not be presented as a new model-effectiveness evaluation.

If compatibility cannot be achieved, this binding decision will be revisited based on the identified obstacle. Compatibility and performance are not already proven.

Technical sources: [onnxruntime_go and requirements](https://github.com/yalue/onnxruntime_go), [models supported by sklearn-onnx](https://onnx.ai/sklearn-onnx/supported.html), [scikit-learn model persistence guide](https://scikit-learn.org/stable/model_persistence.html).

These three decisions supersede the earlier Python-core and separate live Python inference-service proposals in `ids-development-plan-faze1.md`. That document was a discussion draft and has been deleted by the user; M12–M14 are the current reference for language responsibilities.

<a id="m15"></a>
### 5.15. M15 — Our own CRS-supporting rule engine

**Implementation / verification status:** The engine has not been developed; compatibility has not been verified.

**Scope and open boundaries:** Coraza is not the product engine; exact supported behavior and libraries remain open.

**Related decisions:** M16, M18, M19, M20. **Open detail records:** A02, A03, A11.

**Status: Approved; the engine is not yet developed and CRS compatibility is not verified.**

**Decision:** We will develop our own HTTP rule engine in Go for Phase 1. It will be designed to read and execute OWASP CRS rule files without translating each into a proprietary rule format. This supersedes the proposal to use Coraza as the product's rule engine.

**Rationale:** Manage HTTP processing and rule evaluation within our architecture, taking responsibility for the engine while using existing CRS rules.

CRS support is more than reading files or executing their regexes. We will support the required SecLang/SecRule syntax, field selection, transformation order, operators, processing phases, chained conditions, per-request variables, and score operations for the targeted CRS version. Specialized detection operations and matching libraries will be selected separately; developing our own engine does not mean writing every underlying library from scratch.

The engine's HTTP input contract will preserve information required by the rules. Initial parsing must not lose repeated parameters, encoded forms, or required body content. Parsing and rule-specific transformations will have clearly separated responsibilities. M16 makes this distinction concrete; the technical data structure has not been selected. Persistent records will continue to be masked under M11.

**Compatibility criteria:** M18 pins the target CRS version to 4.30.0. M19 defines the initial rule groups, and M20 selects PL1 as the initial sensitivity level; the exact active rule list and dependencies will be clarified separately. Required behavior will be verified using normal and attack examples, appropriate CRS tests, and comparisons with reference-engine results. Unsupported directives or operators will not be silently skipped; inability to execute a rule will be reported explicitly. Partial support will not be presented as full CRS compatibility.

Phase 1 retains its SQLi, request-borne XSS, and path traversal scope. The engine produces rule findings and scores, which are evaluated with ML and profile results under M04 and M10. A CRS score is not directly treated as an ML probability. Under M09, analysis uses request copies; blocking actions in CRS rules do not authorize blocking the protected application's requests in Phase 1.

This decision increases the engine's scope; the development sequence and compatibility test plan will be prepared separately. Only the architectural choice is recorded here.

Technical sources: [OWASP CRS overview](https://coreruleset.org/docs/), [CRS rule files](https://github.com/coreruleset/coreruleset/tree/main/rules).

<a id="m16"></a>
### 5.16. M16 — Received content, parsed view, and analysis status

**Implementation / verification status:** The product data structure is not implemented.

**Scope and open boundaries:** Received content, parsed views, and analysis status are separate; representations remain open.

**Related decisions:** M03, M05, M11, M17. **Open detail records:** A02, A03.

**Status: Approved; the data structure is not yet implemented.**

**Decision:** Common HTTP request data will carry three distinct information groups:

| Information group | Content and responsibility |
| --- | --- |
| Received content | Method, encoded request target, header values, and body bytes received from the proxy or offline source before IDS transformations |
| Parsed view | Fields extracted from the path, query, cookies, and supported body formats, with access preserving value origins and necessary structural information |
| Analysis status | Inspection coverage information, including whether content was received completely, size-limit truncation, unsupported content, and parsing errors |

1. The parsed view will be produced without overwriting received content. Content supplied by the proxy will not be treated as a byte-for-byte copy of network packets; proxy changes will be examined during integration.
2. Repeated header and parameter values will not be reduced to one value. For example, both values in `q=kitap&q=kalem` will be preserved. Detailed representations of nested JSON fields, types, and duplicate keys will be defined separately; information will not be silently discarded.
3. Encoded content and decoded values will be distinguished. For example, the received query `q=merhaba%20dunya` may be preserved while the parsed view contains `merhaba dunya`. Which decoding happens at each stage will be explicit.
4. Rule-specific transformations will not change shared request data. One rule's lowercasing or additional decoding will not change the starting data for other rules or ML. CRS per-request variable and score updates will be kept in separate execution state.
5. Empty or absent fields will be distinguished from unreadable ones. For example, if the body was fully received but JSON parsing failed, checks that can use the available received content may continue. M05 will report that checks requiring JSON fields could not complete.
6. The CRS engine, ML feature extractor, and profile checks will use the representation they need. M13 will define which representation each ML feature uses, consistently across training and live use.
7. Shared data may be read-only; each layer need not receive a separate copy of the entire request. Data will be retained only for the lifetime needed for analysis. Body-size and inspection-time limits will apply; numeric limits will be chosen separately. Truncated content will not be presented as fully received.
8. Access to actual content during analysis does not mean writing it to persistent records. M11's masking and retention policy remains applicable.

**Rationale:** Prevent early data loss, layers changing each other's inputs, and incomplete analysis being interpreted as normal results; allow reuse of shared parsed fields.

This decision does not require every layer to finish all parsing in a single pass or use the same transformed value. M17 defines content scope. Go structs, field-access APIs, and memory-management details will be defined in subsequent technical design.

<a id="m17"></a>
### 5.17. M17 — Phase 1 HTTP content scope

**Implementation / verification status:** The product scope is not implemented; the pilot extractor has narrower coverage.

**Scope and open boundaries:** Content types are defined; parser behavior and limits remain open.

**Related decisions:** M03, M05, M16. **Open detail records:** A02, A08, A11.

**Status: Approved; support is not yet implemented.**

**Decision:** The initial release's inspection scope will be:

| Request section / content | Phase 1 scope |
| --- | --- |
| Method, path, and query parameters | Inspect; preserve repeated values |
| Headers and cookies | Inspect; mask or omit sensitive values in persistent records under M11 |
| `application/x-www-form-urlencoded` | Parse and inspect form fields |
| `application/json` | Inspect fields, including nested objects and arrays |
| `multipart/form-data` | Inspect text fields, file names, and file metadata |
| File contents within multipart | Do not analyze in the first release; report as outside scope |
| `text/plain` | Inspect as text without splitting into structured fields |
| XML | Defer structured XML support |
| Compressed request bodies | Defer decompression; undecoded bodies are not considered inspected |
| WebSocket messages and response bodies | Outside the initial release scope |

**Rationale:** Cover request formats used by web applications, such as forms, JSON, and multipart, while treating content requiring additional parsers and resource management as separate development steps.

An unsupported body will not cause inspection of other available request sections to be abandoned. For example, path, query, and header checks may continue even if an XML body cannot be structurally inspected. Results will identify inspected and uninspectable sections; this alone is not an attack alert. Supported content that is incomplete due to parsing errors or limits will also be reported under M05 and M16.

This table defines system content scope; it does not establish that every ML model has been validated on every content type. Each layer's inspection coverage will be tracked separately. CRS compatibility will also be defined with this HTTP scope in mind; checks requiring XML or response data will not be reported as having run.

Size limits, charset/character-encoding behavior, detailed JSON field representation, the full multipart file-metadata list, MIME variants, and invalid/missing Content-Type behavior remain undecided. This decision alone does not settle them.

<a id="m18"></a>
### 5.18. M18 — Pin the CRS version

**Implementation / verification status:** Version sources exist; engine integration is not verified.

**Scope and open boundaries:** Target v4.30.0; upgrade validation and the active list remain open.

**Related decisions:** M15, M19, M20. **Open detail records:** A11.

**Status: Approved; version selected, engine compatibility not yet verified.**

**Decision:** The initial compatibility target for our Go rule engine is **OWASP CRS 4.30.0**. Rule behavior, required engine capabilities, and compatibility tests will be defined against this version. The published `v4.30.0` tag will be the reference, not the changing `main` branch or a dependency that automatically follows the latest release.

**Rationale:** Use identical rule content during development and testing, reproduce errors, and compare engine behavior against a specific reference.

When moving to a new CRS version, changes and compatibility tests will be reviewed and the target version updated deliberately. Pinning does not mean ignoring future security fixes.

This decision does not mean every CRS rule is enabled or supported in Phase 1. M19 defines initial rule groups, and M20 selects PL1. The exact list, configuration and processing dependencies, and test coverage will be clarified separately. M17's HTTP content scope remains applicable. Downloading the source archive also does not mean engine integration is complete.

Reference: [OWASP CRS v4.30.0 release](https://github.com/coreruleset/coreruleset/releases/tag/v4.30.0).

<a id="m19"></a>
### 5.19. M19 — Initial rule groups and expansion direction

**Implementation / verification status:** Sources exist; engine support for selected rules does not.

**Scope and open boundaries:** Groups 942, 941, and the path traversal subset of 930; exact IDs remain open.

**Related decisions:** M15, M17, M18, M20. **Open detail records:** A11.

**Status: Approved; rule-engine support has not yet been developed.**

**Decision:** CRS 4.30.0 engine development will start with support for executing SQLi, request-borne XSS, and path traversal rules, including the common setup and execution operations they require. Expansion toward the full CRS scope is a later goal; full compatibility is neither achieved nor committed for Phase 1.

| Initial target | Starting source within CRS |
| --- | --- |
| SQLi | `rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf` |
| XSS | `rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf` |
| Path traversal | Relevant rules in `rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf`; starting references 930100 and 930110 |

The 930 file is named for LFI (Local File Inclusion); its path traversal rules appear under `Directory Traversal Attacks`. The same file also contains operating-system and restricted-file access checks. Choosing this file as a study source does not include all its detections in the initial scope.

CRS rules will not be rewritten as individual Go functions. The engine will execute field selection, transformations, matching, and actions described by the selected rules. Original CRS sources will be preserved; loaded files and active rules will be tracked through configuration. The exact rule-ID list will be built from M20's PL1 scope and dependency inspection.

Required initialization settings, score variables, phase and skip controls, chained conditions, and any auxiliary data files will be evaluated together. Extracting detection rules while omitting their dependencies is not a correct implementation. M15's compatibility verification and explicit reporting of unsupported operations remain applicable.

**Rationale:** Follow a development sequence matching the initial product's attack scope and reuse common engine capabilities for later CRS groups.

M17's HTTP content scope applies. XML, response bodies, and other deferred content will be addressed separately when expanding CRS compatibility. This decision does not retrain the existing ML model or change the existing data split.

<a id="m20"></a>
### 5.20. M20 — Initially PL1, with expansion to higher levels

**Implementation / verification status:** PL1 decision approved; execution support not verified.

**Scope and open boundaries:** PL1 within selected groups; PL2–PL4 will be considered as development progresses.

**Related decisions:** M15, M18, M19. **Open detail records:** A11.

**Status: Approved; engine support is not yet implemented or verified.**

**Decision:** Initially target only **PL1** for CRS 4.30.0. This applies to M19's SQLi, request-borne XSS, and path traversal scope; it does not mean supporting every CRS PL1 rule. Common setup, variables, scoring, and execution controls required by the selected rules will also be supported.

1. PL2, PL3, and PL4 rules will not be active in the first release. Configuring an unsupported level will produce an explicit error; partial results will not be presented as if the higher level were working.
2. **PL2, PL3, and PL4 support** will be expansion goals as development progresses. Each transition will evaluate required engine behavior, compatibility tests, false positive effects on normal traffic, and performance. Higher levels are not completion requirements for the first release.
3. PL selection will be configured; a rule match will not automatically raise the level. Once higher levels are supported, the selected level will include lower-level rules within the supported scope.
4. PL is not a rule's execution phase (`phase`), severity, or alert threshold. Phase ordering and flow controls such as `skipAfter` will be preserved; extracting file lines based only on PL tags is insufficient.

**Rationale:** Limit initial engine development and verification scope, and evaluate higher levels' additional detections and false positive effects in a controlled way. PL1 does not guarantee zero false positives or detection of every attack.

This decision concerns CRS rule sensitivity levels only; it does not change the scope of the ML or application-profile layers. Exact active rule IDs and dependencies will be defined separately.

<a id="acik"></a>
## 6. Open decisions — A01–A11

**11 main topics do not mean 11 individual approvals.** Each record contains multiple subdecisions. These are tracking IDs for open work, separate from the M decision numbering. When part of a topic is settled, its remaining questions stay visible. The timings below are a proposed dependency order, not newly approved architecture.

<a id="a01"></a>
### 6.1. A01 — Proxy, TLS, and copy transfer

**Status:** Open.

**Known / approved basis:** M02 and M09 approve an existing reverse proxy, TLS termination, and request-copy analysis that does not hold up the application.

**Questions to answer:** Which proxy? Which protocol/API transfers the copy? How will body integrity, buffering, and large/slow uploads be handled? How will proxy-to-application TLS and certificate management be configured? What happens if the IDS is unavailable?

**Dependencies:** M01/M02/M09; considered together with A02, A08, and A09.

**Needed when:** Before live-traffic integration; selecting the proxy product is not required to start the first offline engine.

<a id="a02"></a>
### 6.2. A02 — HTTP data contract and parsing

**Status:** Open.

**Known / approved basis:** M03, M16, and M17 define basic fields, three information groups, preservation of repeated values, and product content scope.

**Questions to answer:** What are the Go data types and field-access interfaces? How are raw URI and decoded path/parameters distinguished? How are repeated headers, query/body placement, JSON types, and duplicate keys represented? How are charsets, MIME variants, invalid/missing Content-Type, malformed encoding, HTTP versions/methods, and size limits handled? What is the full multipart file-metadata list?

**Dependencies:** M03/M05/M16/M17; A03, A08, A10, and A11.

**Needed when:** The minimum contract for the first engine's selected fields before coding; full content details before implementing each relevant parser.

<a id="a03"></a>
### 6.3. A03 — Layer responsibilities and common result contract

**Status:** Open.

**Known / approved basis:** M04: separate findings; M05: visibility of incomplete analysis; M10: combined decisions.

**Questions to answer:** What exactly are each layer's inputs and responsibilities? How are findings, field locations, rule/model versions, scores, errors, and coverage carried? How are no match, not executed, and partial analysis distinguished? How will engine-library, CLI, or service output be presented?

**Dependencies:** M04/M05/M10/M11; A02, A04, A06, A09, and A11.

**Needed when:** The first rule engine's minimum output contract before starting; the combined layer contract before integration.

<a id="a04"></a>
### 6.4. A04 — Manually defined application profiles

**Status:** Open.

**Known / approved basis:** M06/M07: application settings are separate; no automatic traffic learning initially. M11: profiles may identify sensitive fields.

**Questions to answer:** What are the profile file/interface and validation rules? How are path, method, and field selectors expressed? How are expected types and fields defined? Which profile belongs to which application? What result does an incorrect or missing profile produce? How do profile exceptions interact with attack checks?

**Dependencies:** M06/M07/M11; A02, A03, A06, and A09.

**Needed when:** Before developing the profile layer and application-specific settings; not a blocker for the first isolated rule demo.

<a id="a05"></a>
### 6.5. A05 — ML approach and the role of anomaly detection

**Status:** Open.

**Known / approved basis:** The current pilot is a supervised Random Forest; the final model is not selected. Automatic profile learning from traffic is a different question from an unsupervised model approach.

**Questions to answer:** Which attacks/inputs will the initial product ML layer target? How will supervised classification be used? Will an unsupervised anomaly model be a separate experiment or a later stage? How will transfer to an unfamiliar application be measured? How will model updates and version selection be managed?

**Dependencies:** M04/M07/M12/M13/M14; A07 and A10.

**Needed when:** Before developing a new product model and integrating ML into the product; not required for the first rule engine.

<a id="a06"></a>
### 6.6. A06 — Score combination and alert policy

**Status:** Open.

**Known / approved basis:** M10: layer scores will be evaluated by the decision mechanism; direct averaging, weights, and thresholds have not been selected.

**Questions to answer:** What does each score represent? How will rule severity and CRS totals relate to the ML score? How is the same pattern found by multiple layers evaluated? How do missing results and profile exceptions affect decisions? Which data will be used to choose thresholds, and how will false positives be investigated?

**Dependencies:** M04/M05/M10; A03, A04, A07, and A10.

**Needed when:** Before developing the combined alert mechanism. Rule scores from the first engine do not replace this final policy.

<a id="a07"></a>
### 6.7. A07 — Data, evaluation, and success criteria

**Status:** Open.

**Known / approved basis:** The existing 1,000 records form a pilot; the test has been observed. There are no numeric product-success targets.

**Questions to answer:** Where will new labeled data come from? How will normal application traffic and selected attacks be represented? How will cross-application evaluation be set up? How will training/validation/final splits and leakage through repetition be managed? What acceptance limits measure layer and system success? How will ML experiments and rule compatibility be reported separately?

**Dependencies:** M04/M09/M10/M13/M15; A05, A06, A08, and A11.

**Needed when:** Limited first-engine acceptance examples before starting; a broader evaluation setup before product-effectiveness claims or a new ML experiment.

<a id="a08"></a>
### 6.8. A08 — Performance, resource limits, and overload

**Status:** Open.

**Known / approved basis:** M09: copy-based analysis and fast results; latency including queues, throughput, p95, and resource use will be evaluated.

**Questions to answer:** What are the target hardware, traffic, and request sizes? What are the latency and capacity targets? How are queues, worker count, concurrency, memory, and analysis-time limits defined? How are lost copies or incomplete analysis reported under load? What are startup/shutdown and configuration-change behaviors?

**Dependencies:** M05/M09/M12; A01, A02, A10, and A11.

**Needed when:** The first engine's execution arrangement and necessary basic limits at the start; load/capacity policy before live integration.

<a id="a09"></a>
### 6.9. A09 — Sensitive data, records, access, and retention

**Status:** Open.

**Known / approved basis:** M11: actual content is analyzed; recorded values are masked or omitted; no complete raw-request recording by default.

**Questions to answer:** Which fields and locations are sensitive? How are finding/snippet/error records protected? How do proxy logs and temporary files follow the policy? What are the record schema, storage, retention periods, and access permissions? What will the alert API/dashboard expose?

**Dependencies:** M06/M07/M11; A01, A03, A04, and A08.

**Needed when:** First-engine output must comply with M11 from the start; detailed policy before persistent recording, management interfaces, and live integration.

<a id="a10"></a>
### 6.10. A10 — Feature contract and ONNX migration

**Status:** Open.

**Known / approved basis:** M12–M14 approve shared Go feature extraction, Python training, and the ONNX Runtime direction; the binding library is a candidate and compatibility is unverified.

**Questions to answer:** What are the feature names, ordering, types, and raw/decoded sources? What do byte/character lengths and repetitions mean? Will the finite guard and training-fitted 21→18 selection run inside ONNX or Go? How will model/feature versions be matched? What are the cgo/native dependency versions and target platforms? How will score-difference tolerance and equivalence around thresholds be tested?

**Dependencies:** M03/M12/M13/M14/M16; A02, A05, A07, and A08.

**Needed when:** Before implementing the Go feature extractor and migrated model; not required for the first rule engine.

<a id="a11"></a>
### 6.11. A11 — CRS scope, SecLang support, and compatibility

**Status:** Open.

**Known / approved basis:** M15/M18–M20: our own engine, CRS 4.30.0, SQLi/XSS/path traversal, and PL1. Exact active rule IDs have not been chosen.

**Questions to answer:** Which rule or rules will run first? What are their load order, setup/control rules, and auxiliary file dependencies? Which SecLang selectors, operators, transformations, actions, macros, chains, and phase/skipAfter behaviors are needed? How will regex and specialized detection libraries be chosen? How will targets outside M17's scope be reported? Which CRS regression tests and reference engine/version will be used?

**Dependencies:** M03/M05/M15/M16/M17/M18/M19/M20; A02, A03, A07, and A08.

**Needed when:** First-rule selection and minimum behavior before starting; expand the list and tests incrementally across SQLi/XSS/path traversal.

### 6.12. Unselected technologies from the previous draft

| Candidate in the old draft | Current interpretation | Tracking |
| --- | --- | --- |
| Python core, FastAPI/Uvicorn, Python workers | Superseded as the current architecture by the Go product-core decision; live Python inference service is not the default | M12–M14; A03/A08/A10 |
| Coraza as the product engine | Superseded by our own SecLang engine in M15; may be a learning/reference source | M15; A11 |
| NGINX | Existing-proxy requirement approved; NGINX itself not selected | A01 |
| YAML/Pydantic profiles | Manual profiles approved; format and validation technology not selected | A04 |
| SQLite | Alert storage product not selected | A09 |
| CLI/API, Jinja2, or another dashboard | Presentation and service technologies not selected; the old Python-framework proposal does not override the Go decision | A03/A09 |
| Docker Compose, a single Linux machine | Earlier draft proposal/assumption, not an approved deployment standard or platform decision | A01/A08/A10 |
| HTTPX, Locust, or other test tools | Product-testing candidates, separate from existing Python experiment tests; product test tools not selected | A07/A08/A11 |

### 6.13. Topics identified during review, not yet discussed

These are not newly approved requirements. They are questions linked to open topics so they are not forgotten when implementation begins:

1. **Trust boundary — A01/A04/A09:** Who can access the copy-ingestion service? How will application/profile identity come from the trusted integration, and how will a client be prevented from selecting another profile through a header?
2. **Rule and configuration lifecycle — A08/A11:** What happens if startup validation fails? Will changes initially require a restart, or is later reloading needed? Remote rule loading from users must not be assumed to exist.
3. **Incompatible component versions — A03/A10:** How will the system report mismatches between model, feature-definition, and configuration versions?
4. **Deployment and operations — A01/A08/A09/A10:** What are the target OS/architecture, native ONNX dependency, installation format, health/capacity indicators, and access-management approach?
5. **Open-source release — A11 and deployment preparation:** Review the project license and CRS/underlying-library notice and distribution requirements before publication; this document does not select a license.

### 6.14. Retained evaluation proposal — not yet approved

1. **Success measurement:** Build on the user's proposal to evaluate individual layers and final decisions. In addition to overall accuracy, measure attack recall, false positive rate on normal traffic, precision of generated alerts, analysis coverage, and latency. Evaluate each layer within its responsibilities and attack scope. On the same evaluation data, inspect separate layer results, the combined result, and the difference when a layer is removed. Numeric success targets have not been defined.

This proposal will be discussed under A07 and A06; its inclusion here does not approve a numeric acceptance threshold or evaluation policy.

<a id="ilk-motor"></a>
## 7. Proposed starting decisions for the first engine

**Status: Proposed discussion order, not yet finalized as an implementation plan.** The user approved preparing this handoff document; that approval does not automatically approve the four technical choices below.

| Order | Decision to discuss | Required decision output | Related open topics |
| --- | --- | --- | --- |
| 1 | M21 proposal: engine startup and per-request execution arrangement | Boundary between shared prepared rules and per-request working state | A08/A11; consistent with M16 |
| 2 | First real CRS rule/rule set | Exact rule IDs and required SecLang/setup/data-file list | A11 |
| 3 | Minimum input/output contract | Supported HTTP fields and representation of findings, scores, errors, and incomplete analysis | A02/A03/A09 |
| 4 | First-engine acceptance criteria | Normal/attack examples, expected behavior, and reference comparison | A07/A11; necessary basic performance limits in A08 |

### 7.1. Next discussion: M21 proposal

**Not yet approved:** Read, validate, and prepare rules when the application starts. Each request should use those prepared rules, while its variables, matches, and scores belong to its own execution state.

Rationale: Reduce repeated file reading/preparation per request and prevent concurrent requests' results from mixing. For example, request A's SQLi finding and score increase must not carry over to request B.

M16 already approves preventing transformations from interfering through shared input and separating CRS per-request state. M21 additionally proposes startup preparation and shared rules. This proposal does not select worker counts, parallel execution of all layers, or hot reloading.

### 7.2. Boundary around the first rule

930100 and 930110 are starting references in M19. An educational demo exists for 930110; that does not finalize it as the first rule to implement. Examples such as 930120/930121 from the PL demo are not automatically included in the initial product scope either.

### 7.3. Interpreting the transition to coding

These four topics are the proposed minimum decision group for a first working offline rule engine. Technical inspection may uncover further dependencies or obstacles; four approvals do not guarantee that all product decisions are settled. At this stage, the user expects the necessary open choices to be discussed before coding begins.

Example first-engine flow: **prepared HTTP example → selected real CRS rule → finding/score/analysis status**. Proxy/TLS, ML, and profile integration may follow later; they are not removed from the Phase 1 product goal. Subsequent work order will be clarified as the relevant decisions are discussed.

<a id="devir"></a>
## 8. Session handoff and working rules

1. Communicate clearly in English using numbered points. Maintain plans in English until the user requests otherwise. The user knows Python and is learning Go and ML development. Explain the reason for each technical decision and provide a small example.
2. Discuss decisions one at a time. When the user approves one, add/update its M record and identify which subquestion in the related A record is resolved. Do not ask again for approval of M01–M20.
3. Keep proposals, decisions, implementation, and verification separate. Do not treat undeveloped features as complete or educational explanations as test evidence. Do not expand document-editing requests into coding.
4. Check current status against source files in every new session. Do not treat future proposals as completed work or remove older report statements from their historical context. If sources conflict, consider their roles/dates and subsequent evidence; report unresolved differences explicitly.
5. Keep new IDS product code, plans, and reports under `/home/esip/Documents/ids-system`. ML experiments, data, training code, and model outputs remain in `/home/esip/Documents/ids-model`. Product files were separated on 4 October 2026; the move is not a reason to change existing experiments.
6. Do not include source metadata in ML inputs. Do not change the existing split, original data, or model without a reason. Preserve the fact that test data has already been observed; discuss a separate version and evaluation setup if a new experiment is needed.
7. Preserve M11's recording privacy and M05's incomplete-analysis principle throughout development. Sensitive fields are not exempt from analysis; raw matches are not automatically written to persistent records.
8. Once coding begins, implement only the scope agreed with the user. Listing an open topic in this document is not an instruction to build all components at once.

**First task in a new session:** After verifying sections 1–2 and their sources, discuss M21 with the user unless a newer approval exists in the conversation. If the user selects another open topic, continue there instead.

<a id="kaynaklar"></a>
## 9. Source guide and historical documents

Product documents and CRS sources are in `ids-system`. Links to ML sources point to the sibling `../ids-model/` directory. Recheck links if the relative location of these folders changes. The user deleted the old `ids-development-plan-faze1.md`; explanations of past choices are retained without linking to that file.

| Source | Role and interpretation |
| --- | --- |
| [This main plan](ids-system-plan-faze1.md) | Current architecture choices and open-decision index; not a substitute for implementation evidence |
| [README](../ids-model/README.md) | Python pilot, environment, and results summary; not the full product goal |
| [Split record](../ids-model/data/processed/http-mini-splits-v1/split_report.json) and [split report](../ids-model/reports/http-veri-ayrimi.md) | Current pilot split; “not yet trained” describes the historical split-preparation stage |
| [Training record](../ids-model/models/rf-baseline-v1/run.json), [first training report](../ids-model/reports/ilk-random-forest.md), and [pipeline](../ids-model/models/rf-baseline-v1/pipeline.joblib) | Model/preprocessing, parameter, and validation evidence; the test flag describes the training stage |
| [Test record](../ids-model/reports/rf-baseline-v1-test/test_report.json) and [test explanation](../ids-model/reports/rf-baseline-v1-test/README.md) | Evidence of the subsequent fixed-model test; explicitly states that the model did not retrain |
| [Feature report](../ids-model/reports/oznitelik-cikarici.md) and [extractor code](../ids-model/scripts/extract_features.py) | Existing Python feature calculation; not evidence that Go product scope is implemented |
| [Training walkthrough](../ids-model/reports/random-forest-egitim-sureci.md) and [notebook](../ids-model/notebooks/04_ilk_random_forest.ipynb) | Educational explanation of the pilot |
| Old technology draft (deleted by the user) | Discussion draft; M12–M14 supersede the Python-core/live-Python-service direction. NGINX, SQLite, Compose, and similar proposals were not automatically selected |
| [Initial ML-stage plan](../ids-model/ids-ilk-asama-plani.md) | Plan for an earlier experimental stage, not the current product implementation sequence |
| [Go learning and WAF study plan](ids-go-ogrenme-ve-waf-inceleme-plani.md) | Learning resource, not evidence of architecture selection or completed development |
| [CRS 4.30.0 sources](coreruleset-4.30.0) | Local version reference; original rules are preserved. Available sources do not establish full support |
| [930110 demo](reports/crs-930110-kural-demosu.md) and [PL1/PL2 demo](reports/crs-pl1-pl2-calisma-sirasi.md) | Educational execution walkthroughs. Any statement that PL has not been selected describes the stage before M20 |

**Precedence:** Read current architecture choices from approved decisions in this document; verify what the application actually does from code and relevant experiment records. A newer file does not invalidate all older records: for example, the test report does not change training settings but complements the training record with a later evaluation. Update this document if the user makes a newer explicit decision.

<a id="sozluk"></a>
## 10. Glossary

| Term | Meaning in this project |
| --- | --- |
| IDS | A system that detects and reports suspicious/attack activity; Phase 1 does not automatically block |
| WAF | A system that applies security checks to web-application HTTP traffic; may block depending on its operating mode |
| CRS | OWASP Core Rule Set: rules and supporting content read/executed by an engine, not a standalone IDS application |
| SecLang / SecRule | The language/directive expressing rule targets, operators, transformations, and actions; requires more than copying regexes |
| PL | Paranoia Level: sensitivity level of active rule coverage. PL2 includes the lower level within selected groups; not a rule's severity or execution order |
| Phase | A rule's HTTP processing stage, independent of PL; a phase-1 PL2 rule may execute before a phase-2 PL1 rule |
| Finding | A layer's result, such as a match, model score, or profile mismatch |
| Alert | A result the decision mechanism considers worth reporting after evaluating findings; not every finding automatically becomes an alert |
| Preprocessing | Numeric-input validation/transformation/selection before the model; learned preprocessing in the pilot is fitted only on training data |
| Model inference | A trained model producing a score/class for new input; not retraining during validation or testing |
| Feature extraction | Calculating numeric model inputs from HTTP requests; the product targets the same Go code for training and live use |
| ONNX / ONNX Runtime | Respectively, a portable model format and the engine that executes its computation |
| Incomplete analysis | An inability to inspect part of a request or perform a required check; not a normal result or proof of attack on its own |
| False positive rate | Fraction of normal records incorrectly predicted as attack/anomalous: FP/(FP+TN) |

<a id="kontrol"></a>
## 11. Document validation and update history

### 11.1. Checks for this restructuring

1. Decision texts, rationale, examples, and boundaries for M01–M20 were retained from the previous document; navigation and implementation/open-topic summaries were added.
2. The M21 proposal and four first-engine discussion topics were not added to the approved-decision index.
3. The previous 11 open topics are tracked as A01–A11; newly identified, undiscussed questions are marked separately.
4. Pilot numbers were compared with training, split, and test records. Local links, section numbering, and decision IDs are checked.
5. This work is not a model or application test; it does not verify the CRS engine, ONNX migration, or product performance.

### 11.2. Procedure for subsequent updates

When a decision is approved, update its M ID, related A record, and index together. When implementation is complete, add code/output evidence to the separate status field. When verification is performed, state its method, date, and scope. Do not rewrite historical experiment records merely to make them resemble current status.

**3 October 2026 restructuring:** The main plan was reorganized with a starting summary, verified pilot status, scope boundaries, architecture diagram, preserved M01–M20, A01–A11 open topics, proposed first-engine decisions, handoff rules, and source guide. This restructuring does not approve a new technical proposal.

### 11.3. Separating product and ML directories — 4 October 2026

At the user's request, product development was separated into `/home/esip/Documents/ids-system`. The main plan, Go/WAF learning plan, two CRS demo reports, CRS 4.30.0 sources and ZIP archive, [project introduction form](proje-dersi-tanitim-formu-2026-doldurulmus.docx), and the interrupted Go download under `.tools` were moved there. `.tools/downloads/go1.27.1.linux-amd64.tar.gz.part` is an incomplete archive, not an installed Go toolchain or usable dependency. The download was not resumed.

Data, Python training/feature-extraction code, the model, notebooks, ML reports, and the Python environment remained in `ids-model`. The current main plan exists only in `ids-system`. M01–M20 and M21's proposal status were unchanged. At the time of the move, `context.md` had not yet been created, as requested by the user.

The project introduction form was moved with its historical content unchanged; its Python-engine and framework proposals are not current architecture choices. Historical decision statements in the Go/WAF learning plan and CRS demos should also be read alongside this main plan for current choices.

The user installed Go independently; that session verified `go version` output as `go version go1.26.8-X:nodwarf5 linux/amd64`. The user wants to perform package installations themselves; provide and explain installation commands. No installation, model training, or Go application development occurred during the move.

### 11.4. English documentation — 4 October 2026

The user subsequently requested a short `context.md`, which was created, and then switched the working language to English. This main plan and `context.md` were translated into English. Communication and plans will remain in English until the user requests otherwise. Decision IDs, approval states, technical values, file names, and link targets were preserved; existing anchor IDs were retained for link compatibility. No product code was developed as part of the translation.
