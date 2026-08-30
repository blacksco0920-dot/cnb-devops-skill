# CNB OpenAPI

Last verified: 2026-08-30

Use the live specification for endpoint schemas:

- API and interactive documentation: <https://api.cnb.cool>
- Swagger JSON: <https://api.cnb.cool/swagger.json>

This reference records decision boundaries, not a duplicate endpoint catalog.

## Authentication

CNB OpenAPI uses an `Authorization: Bearer ${token}` request header. Set
`Accept` to a response type listed by the live specification, commonly
`application/json`.

Obtain a token from an existing approved secure store. If none exists, direct
the authorized human to **Personal settings → Access token → Add access token**
and request only the repository/use scope and operation scope required for the
task. Never place a token in a URL, Git remote, command argument, log, example
value, ordinary repository, or AI conversation.

CNB pipelines expose a temporary `CNB_TOKEN` that is destroyed after the build.
Do not copy it out of the job or turn it into a long-lived credential.

## Read-only discovery

Inspection remains read-only unless the user separately requests a mutation.
Use the live specification to inspect, as needed:

- current user identity;
- groups and the caller's access role;
- repositories and repository/build settings;
- default branch;
- build status and build/deployment history.

Choose a repository organization from the group results. The current user's
login `username` is an identity, not proof that a same-named organization owns
the repository. With one writable group the choice may be unambiguous; with
multiple writable groups, report them and obtain the intended group.

Read only the minimum evidence needed for the question. A status request does
not authorize enabling builds, triggering a pipeline, creating a repository,
approving a deployment, or changing a Secret file.

## Mutation boundary

Repository creation, build-setting changes, manual build triggers, deployment
triggers, and approvals each require an explicit user request for that state
change. State the exact repository, environment, and expected commit before the
write. Re-read the relevant state after the write and stop on an unexpected
identity or permission response.

Production has an additional gate: explicit production intent, a complete
tested candidate manifest, and the configured approval. An API trigger by
itself is not safe promotion and must never be described as one.

## Secret repositories

Secret repositories are created and edited through CNB Web. They cannot be Git
cloned or locally pushed. Pipelines reference files with `imports`,
`optionsFrom`, or `settingsFrom` subject to CNB's file-reference checks.

The authorized Secret maintainer constrains every file with the applicable
`allow_slugs`, `allow_events`, `allow_branches`, and `allow_images` fields. Once
such rules are declared, all relevant rules must pass. The AI handles variable
names and `secret receipt`s only; it does not ask for values or invent a Secret
write API.

## Native deployment UI

`.cnb/tag_deploy.yml` defines named environments. Selecting an environment
triggers the matching `tag_deploy.<environment>` pipeline for the selected tag.

Before relying on the UI for production, configure and verify:

- deployment permissions in addition to repository write permission;
- a staging environment requirement;
- required candidate annotations that bind the immutable evidence;
- the named approver requirement;
- the matching production event in `.cnb.yml`.

All configured `require` items must pass. A UI approval is still only approval
for the candidate represented by the tag; the production pipeline must reload
and compare the complete tested digest map, and must not rebuild it.

## Common errors

- `403`: the token lacks the exact repository/use or operation scope. Do not
  widen unrelated scopes or bypass production approval.
- `406`: verify the live response content type and any encoded repository path
  segment against the Swagger definition.
- Registry `unauthorized`: diagnose OCI Registry credentials and repository
  policy, not the CNB API token by default.
- CNB build `success` with an unhealthy server or failing HTTPS: build evidence
  passed; runtime or public evidence did not. Continue at that boundary instead
  of rebuilding automatically.

## Official sources

- <https://docs.cnb.cool/zh/develops/openapi.html>
- <https://docs.cnb.cool/zh/guide/access-token.html>
- <https://docs.cnb.cool/zh/repo/secret.html>
- <https://docs.cnb.cool/zh/build/file-reference.html>
- <https://docs.cnb.cool/zh/build/deploy.html>
