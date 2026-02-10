# Repository Transfer – Post‑Transfer Checklist

This document describes the **minimum steps required after a native GitHub transfer** (personal → organization) to ensure CI and integrations continue working as expected.

The repository is going to be transferred using **GitHub’s native transfer** method, which preserves:

* Git history, branches, tags
* Issues and Pull Requests
* GitHub Actions workflow files
* Fork relationship with upstream

---

## 1. Access & Ownership

* Confirm the repository is under the [Blockstream](https://github.com/Blockstream) GitHub organization
* Confirm post-transfer access level for @miketlk (primary developer prior to transfer)

---

## 2. CI / GitHub Actions

### Workflows

* Verify workflows are **enabled** (GitHub may auto‑disable them after transfer)

### Secrets

The following **repository secret must be recreated** in the organization repo:

* `CODECOV_TOKEN` (obtain a token for Blockstream at [Codecov](https://about.codecov.io/) or reuse an existing org-level token)

Location:

```
Settings → Secrets and variables → Actions → Repository secrets
```

No other repository secrets were identified.

---

## 3. Codecov

* Re‑add `CODECOV_TOKEN` for this repo under the org’s Codecov configuration
* Verify coverage upload in CI

---

## 4. Branch Protection / Rulesets

* Confirm org‑level rulesets did not override repo‑specific requirements

---

## 5. Fork / Upstream Relationship

This repository remains a **fork** of [LedgerHQ/app-bitcoin-new](https://github.com/LedgerHQ/app-bitcoin-new).

Please verify:

* The “forked from …” relationship is visible in GitHub UI
* Upstream remote is intact

(Upstream merging will continue to work normally.)

---

## 6. Post‑Transfer Validation

* Run CI once and confirm green

---

## 7. Completion

Once the above is verified:

* Transfer can be considered complete
* Any temporary access granted to @miketlk can be reduced to read-only if needed

If anything behaves unexpectedly during transfer, please reach out to Mike Tolkachev via the agreed communication channel before making structural changes (renames, permission resets, CI rewiring).
