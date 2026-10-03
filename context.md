# IDS — Current Working Context

Last updated: 4 October 2026  
Product directory: `/home/esip/Documents/ids-system`  
Main architecture reference: [ids-system-plan-faze1.md](ids-system-plan-faze1.md)

## 1. What is the project?

We are building a general-purpose, open-source HTTP intrusion detection system (IDS), customizable through application profiles. The initial goal is to detect SQLi, request-borne XSS, and path traversal attempts and produce alerts. The first phase does not automatically block requests; prevention is a later goal.

Planned product: a Go core, our own SecLang rule engine, PL1 within selected CRS 4.30.0 groups, ML, and manually defined application-profile layers. Python will be used for model training/evaluation. HTTPS content will come through an existing reverse proxy; the application will proceed without waiting for IDS decisions. These are design decisions, not existing working features.

## 2. What has been done so far?

- **IDS product coding has not started.** There is no Go module, working rule engine, proxy integration, or product ML/profile/decision/logging implementation yet.
- The architecture plan is organized: M01–M20 are approved; A01–A11 track open topics. CRS sources, the learning plan, demo reports, and the project introduction form were moved into this directory. The demos are not a working IDS or compatibility tests.
- The earlier Python Random Forest pilot, data, training code, and experiment reports remain in the separate [ids-model](../ids-model/) directory. The pilot was trained and tested but has not been integrated into the product. Its existing test set has already been observed.
- The user installed Go. Last verified output: `go version go1.26.8-X:nodwarf5 linux/amd64`. No Go product build or test has been performed yet.
- The `.part` file under `.tools/downloads/` is an interrupted, incomplete Go download, not an installed tool.

## 3. Where do we continue?

The next open proposal is **M21**: prepare rules at startup and keep each request's variables, matches, and scores in separate execution state. **It is not yet approved.** Next, decide the initial rule scope, minimum input/output contract, and acceptance tests one at a time. See sections 6–7 of the main plan.

## 4. Working notes for the next agent

1. Read this file and the main plan first; verify status against existing files. Do not treat approved architecture as implemented features.
2. Communicate in English using numbered points, and maintain plans in English until the user requests otherwise. Explain decisions and their reasons one at a time; do not approve open proposals on the user's behalf.
4. Product outputs belong in `ids-system`. Do not change the data split, model, or experiment records in `ids-model` without a reason; keep source metadata out of model inputs.
5. Update this short file after meaningful progress: completed work, unfinished work, checks performed, and the next concrete step. Refer to the main plan instead of duplicating architecture details here.
