# Human Handoffs

Last verified: 2026-08-30

Use this reference when a release needs information or a console action that an
AI cannot safely discover or perform. Ask once for the smallest durable
artifact, not repeatedly for the same facts.

## Shared artifacts

### handoff manifest

A `handoff manifest` contains only non-secret project and environment fields,
the responsible role, completion state, and validation result. It never
contains a RoleArn, external ID, UIN, instance ID, target region, IP address,
credential, or formal domain-control artifact. Those values go directly to the
approved secret or control system.

### secret receipt

A `secret receipt` records the variable name, storage location, responsible
role, creation date, expiry or rotation date, and validation state. It never
records the value. A valid receipt prevents the next AI or operator from asking
for an already configured secret again.

### release evidence

`release evidence` is the non-secret chain:

```text
full Git SHA → CNB build identity → complete TCR digest map
→ TAT invocation/result → actual target runtime digest map → HTTPS result
```

Each handoff is either accepted, rejected with one precise correction, or still
blocked. Do not silently convert missing information into a default.

## Application owner

### When

Before a repository is first connected, whenever its deployable topology
changes, and before a candidate is approved.

### Deliver

- Repository URL and governed source/release branches.
- Docker build contexts, target architectures, complete service list, ports,
  health endpoints, dependency order, migrations, and persistent volumes.
- Environment variable names, classification, and owning role; no values.
- Named production approver and the change/rollback owner.

### Exact console steps

1. In GitHub, open the repository, then **Settings → Secrets and variables →
   Actions**. Create or confirm the per-repository `CNB_PUSH_TOKEN`. If its
   `secret receipt` is already accepted, do not request or replace it.
2. In CNB, create the token with access limited to the target repository and
   the minimum code-write scope needed by synchronization.
3. Configure synchronization only for governed branches. Do not use a
   destructive `--mirror` flow that could delete CNB candidate tags.
4. Record the GitHub and CNB full commit IDs after synchronization.

Official guidance:

- <https://docs.github.com/en/actions/concepts/security/secrets>
- <https://docs.cnb.cool/zh/guide/access-token.html>
- <https://docs.cnb.cool/zh/guide/first-repo.html>
- <https://docs.cnb.cool/zh/build/deploy.html>

### Acceptance

The handoff is accepted only when GitHub and CNB resolve the governed branch to
the same full SHA and the repository's real clean build succeeds. The receipt
for `CNB_PUSH_TOKEN` exists without exposing its value.

### Never deliver

Token values, complete environment files, mutable image tags as release
evidence, or permission to delete unrelated CNB refs.

## CNB and TCR administrator

### When

When a project first receives build/push access, when a new customer server
needs pull access, or when a Registry credential is rotated.

### Deliver

- TCR Personal namespace/repository identity and separate push and pull
  endpoints.
- One dedicated programmatic build-push CAM identity, never a main-account
  credential, and one dedicated pull-only CAM subuser for each customer/project
  repository.
- A policy record, rotation date, isolation test result, and `secret receipt`
  for each credential.

TCR Personal is the selected free path within its service limits and has no SLA.
TCR Enterprise service accounts are an optional paid upgrade, not the assumed
free mechanism.

### Exact console steps

1. Confirm the build-push credential belongs to a dedicated programmatic CAM
   identity with only the required repository push/read scope. Then, in
   **CAM → Users**, create a different dedicated programmatic subuser for one
   customer/project repository's pull access.
2. In **CAM → Policies**, create a custom policy based on Tencent Cloud's
   repository-read-only Personal example. Grant only `tcr:Describe*` and
   `tcr:PullRepositoryPersonal` on the target namespace, repository, and
   repository descendants:

   ```json
   {
     "version": "2.0",
     "statement": [{
       "effect": "allow",
       "action": ["tcr:Describe*", "tcr:PullRepositoryPersonal"],
       "resource": [
         "qcs::tcr:<REGION>:uin/<MAIN_ACCOUNT_UIN>:repo/<NAMESPACE>",
         "qcs::tcr:<REGION>:uin/<MAIN_ACCOUNT_UIN>:repo/<NAMESPACE>/<REPOSITORY>",
         "qcs::tcr:<REGION>:uin/<MAIN_ACCOUNT_UIN>:repo/<NAMESPACE>/<REPOSITORY>/*"
       ]
     }]
   }
   ```

3. Only for first-time Registry credential initialization or rotation,
   temporarily add `tcr:CreateUserPersonal` and
   `tcr:ModifyUserPasswordPersonal` on resource `*`.
4. Open **TCR → Personal → Instance management** for that subuser identity and
   initialize or reset its Registry login password. Verify the login, then
   immediately remove the two temporary actions.
5. Treat the resulting Registry username/password as Docker credentials. A
   Tencent Cloud API SecretId/SecretKey is not the Docker Registry password.
6. Enter the build-push Registry credential in the project's CNB Secret file.
   Enter the pull-only Registry credential directly on the target host using
   the approved runtime-secret mechanism. Record only `secret receipt`s.
7. Test three boundaries by digest: the identity can pull its allowed
   repository, cannot push to it, and cannot read another project's repository.

Official guidance:

- <https://cloud.tencent.com/document/product/1141/40540>
- <https://cloud.tencent.com/document/product/1141/41409>
- <https://cloud.tencent.com/document/product/1141/41415>
- <https://cloud.tencent.com/document/product/1141/41596>

CNB SaaS egress addresses change dynamically. Do not create a permanent CNB IP
allowlist or weaken authentication; use TAT or a controlled proxy when a stable
network boundary is required: <https://docs.cnb.cool/zh/faq.html>.

### Acceptance

The pull test by digest passes, the push and cross-project tests are denied, the
initialization-only actions have been removed, and both secret receipts name an
owner and next rotation date.

### Never deliver

Registry passwords, API keys, a shared all-project pull identity, a broad
`tcr:*` long-lived policy, or Enterprise-only service-account instructions
presented as the free Personal path.

## Customer Tencent Cloud administrator

### When

Before a customer-owned mainland-China server can be considered production
ready, and whenever its role, instance, region, or maintenance window changes.

### Deliver

- Main-account UIN, target region, TAT-supported target product and instance ID,
  OS/architecture, outbound connectivity, TAT agent state, and maintenance
  window directly into the approved control locations—not into chat or the
  `handoff manifest`.
- A customer-controlled `cross-account role` trusted to one dedicated
  programmatic CAM subuser or role in the operator account.
- A `secret receipt` for RoleArn, external ID, target region, and target
  instance ID.

### Exact console steps

1. Open **CAM → Roles → New role** and choose **Tencent Cloud account** as the
   carrier. Select the operator account as another main account, then narrow the
   carrier to the dedicated programmatic CAM subuser or role. Never trust a
   human administrator's general identity or every identity in the account.
2. Enable external-ID validation. Keep console access disabled unless a
   separately approved human workflow requires it.
3. Attach a custom least-privilege policy matching the calls made by the exact
   pinned execution artifact. The verified `tcloud-cmd` runtime calls
   `tat:RunCommand`, polls with `tat:DescribeInvocations`, and, when instance
   output is requested, calls `tat:DescribeInvocationTasks`. Scope these calls
   to the intended command and target-instance resources. A CVM ID beginning
   `ins-` uses a `qcs::cvm:...:instance/...` resource; a Lighthouse ID beginning
   `lhins-` uses `qcs::lighthouse:...:instance/...`. Do not interchange them.
4. In the corresponding CVM or Lighthouse console, confirm the TAT agent is
   online. TAT is the remote execution boundary; production deployment does
   not require exposing port 22.
5. In CNB Web, enter RoleArn, external ID, target region, and target instance ID
   directly into the project's production Secret file. Report only the four
   variable names and their `secret receipt`s.
6. Grant the dedicated operator identity `AssumeRole` only for this role. A
   reviewed client must exchange it for temporary SecretId, SecretKey, and
   Token. Record the returned credential expiration in a value-free receipt.
   Choose the shortest `DurationSeconds` that still covers the declared
   worst-case remote timeout, all control-plane work, and an explicit safety
   margin. Immediately before approval, refresh the complete triple whenever
   its remaining lifetime no longer covers that bound, then execute a harmless
   TAT preflight before any release.

Current compatibility gate: do not infer STS support from the plugin README.
The artifact inspected on 2026-08-30 was
`tencentcom/tcloud-cmd:v1.2.0@sha256:04824cba6a59858a2c78d6ddfc75c63a30941c219c85f414b379f425c43e8845`.
After confirming that exact RepoDigest, inspection of `/app/index.js` inside the
image verified that it reads `PLUGIN_TOKEN`, passes Token with SecretId and
SecretKey to the Tencent Cloud SDK, calls `RunCommand`, always polls
`DescribeInvocations`, and calls `DescribeInvocationTasks` when instance output
is requested. Repeat this inspection whenever the selected digest changes; a
tag name or README claim is not transferable capability evidence.

Treat that implementation check as capability evidence, not release evidence.
Production remains blocked until the selected digest receives the complete
temporary credential triple through an approved Secret boundary and passes a
harmless TAT preflight. If a selected artifact does not support all three
fields, use a separate reviewed adapter or SDK client; never fall back to a
long-lived customer key.

Official guidance:

- <https://cloud.tencent.com/document/product/598/19381>
- <https://cloud.tencent.com/document/api/598/35840>
- <https://cloud.tencent.com/document/product/598/13895>
- <https://cloud.tencent.com/document/product/1340/56294>
- <https://cloud.tencent.com/document/product/1340/50821>
- <https://cnb.cool/cnb/plugins/tencentcom/tcloud-cmd/-/blob/main/README.en.md>

### Acceptance

The role trusts only the dedicated programmatic identity, external-ID checking
is enabled, TAT is online, the policy is least privilege, the four static
receipts exist, and the current temporary credential receipt shows enough
remaining lifetime. Until the reviewed STS-capable execution path passes the
harmless preflight with the full temporary credential triple, acceptance is
explicitly **blocked for production**.

### Never deliver

The customer's main-account password or API key, any long-lived customer key,
RoleArn/external ID/UIN/instance/region values in chat or the ordinary manifest,
or a request to expose SSH for the pipeline.

## DNS and ICP administrator

### When

Before a mainland-China public hostname is cut over, and whenever its address,
certificate path, or filing/access-registration state changes.

### Deliver

- FQDN, DNS zone/provider, intended A/AAAA/CNAME value, TTL, old value,
  rollback value, cutover window, and owner in the approved DNS change record.
- ICP filing and required access-registration state for the actual service and
  provider. The `handoff manifest` records only the status and record owner.

### Exact console steps

1. Open the authoritative DNS provider and create a reviewed change containing
   the old, new, and rollback records plus TTL.
2. Complete the applicable mainland-China ICP filing and access-registration
   process before treating the hostname as production ready.
3. Apply the DNS change only in the approved window. Do not pass DNS account
   credentials to the application or pipeline.
4. After propagation, verify authoritative DNS, TCP 80/443, certificate chain,
   and the application's HTTPS behavior independently.

Official guidance:

- <https://cloud.tencent.com/document/product/302/3449>
- <https://cloud.tencent.com/document/product/243/37403>
- <https://caddyserver.com/docs/automatic-https>

### Acceptance

Authoritative DNS returns the approved value, 80/443 reach the intended host,
the certificate is valid for the FQDN, and public application checks pass. If
DNS or filing is pending, report public evidence as pending rather than
rebuilding the application.

### Never deliver

DNS account credentials, registrar recovery factors, domain-control proof in
the ordinary manifest, or an instruction to bypass filing requirements.

## Data owner

### When

Before first production use, every data migration, and every release whose
application rollback may be incompatible with stored data.

### Deliver

- One explicit mode: `none`, `empty`, or `migrate`.
- Database engine/version, encoding, extensions, schema state, migration order,
  persistent volumes, and external stores.
- Encrypted backup location and checksum, restore steps, freeze window, RPO,
  RTO, retention, reconciliation checks, and named recovery owner.

### Exact console steps

1. Create the backup in the customer-approved database/storage system and
   record its checksum without exposing credentials.
2. Restore it into an isolated rehearsal target using the documented procedure.
3. Run technical integrity and business reconciliation checks; record results
   as non-secret evidence.
4. Approve the freeze and migration window only after the rehearsal meets RPO
   and RTO. Keep database recovery as a separate decision from image rollback.

Official guidance:

- <https://www.postgresql.org/docs/current/backup.html>
- <https://www.postgresql.org/docs/current/app-pgdump.html>
- <https://cloud.tencent.com/document/product/362/8191>
- <https://cloud.tencent.com/document/product/362/5756>

### Acceptance

Mode, backup checksum, successful restore rehearsal, business reconciliation,
retention, and recovery owner are recorded. The release evidence states whether
the prior application can safely use the post-migration data.

### Never deliver

Database passwords, decrypted backups, complete production dumps, or a promise
that rolling back an image will roll back a database or persistent volume.

## Production approver

### When

After all staging evidence passes and immediately before one immutable
candidate may be promoted. For customer-account production, this also requires
an accepted customer-administrator handoff and a successful harmless preflight
through a reviewed STS-capable execution path; without them, do not enter
approval.

### Deliver

- Candidate manifest, staging acceptance, change summary, complete service
  digest map, migration/backup decision, maintenance window, recovery owner,
  and exact approval target.
- For customer-account production, the accepted STS execution/preflight evidence
  showing the complete temporary credential triple was supported without
  exposing it.
- An approval or rejection naming one candidate identity; merge approval is not
  production approval.

### Exact console steps

1. Confirm every environment-level blocker is clear. For customer-account
   production, explicitly verify the exact pinned runtime, full temporary
   credential triple, and harmless preflight; an unverified two-field
   configuration is not sufficient.
2. Open the CNB deployment page generated by `.cnb/tag_deploy.yml`.
3. Compare the displayed full commit, controller commit, build identity,
   service set, and every digest with the candidate manifest.
4. Review staging runtime/public evidence and the data owner's decision.
5. Approve only that immutable candidate. A different candidate or changed
   digest requires a new review.
6. After execution, require the actual production digest map and public result
   before accepting the release record.

Official guidance: <https://docs.cnb.cool/zh/build/deploy.html>.

### Acceptance

The named candidate has explicit approval, production uses the same complete
digest map, and the final `release evidence` is recorded atomically. Missing
evidence, changed service membership, or a recovery-required state blocks
approval. Customer-account production also remains blocked until its reviewed
STS-capable execution path and harmless preflight are accepted.

### Never deliver

A blanket or standing approval, approval for a branch or mutable tag, permission
to rebuild in production, or an instruction to normalize a partial failure as
success.

## CNB Secret repository operation

Only an authorized human Secret maintainer performs these steps:

1. In CNB Web, create or select the intended **Secret repository**.
2. Open the intended YAML file in the Web editor; Secret repositories cannot be
   cloned or pushed from a local checkout.
3. Enter the values directly there. Add the narrowest applicable
   `allow_slugs`, `allow_events`, `allow_branches`, and `allow_images` rules.
4. Save through the audited Web flow.
5. Trigger only a harmless authorized validation and confirm that the intended
   pipeline can reference the file while an out-of-scope pipeline cannot.
6. Return only the variable names and `secret receipt`s. Do not paste values
   into chat or an AI prompt.

Official guidance:

- <https://docs.cnb.cool/zh/repo/secret.html>
- <https://docs.cnb.cool/zh/build/file-reference.html>
