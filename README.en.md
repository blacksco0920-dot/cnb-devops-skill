# cnb-devops-skill

[简体中文](README.md) · **English**

Let your AI coding assistant set up **test deployments, production releases, and backup recovery** for your project. Once connected, each update uses the same pipeline, and you can apply the workflow to other projects you manage.

Built for individual developers and small teams who use AI to write code and want to ship their projects. The AI handles configuration files, deployment scripts, and technical records. You make the business decisions, complete any account actions that require you, and decide when to release to production.

**This is a Preview release**, intended for early users willing to report issues. The supported scope and verification results are described below. End-to-end setup with a fresh account, the experience across AI tools, and first-time setup duration still need validation. See the [Preview release notes](docs/releases/v0.2.0-preview.6.md) for the release scope.

## What it helps you do

- **Set up a project:** Check compatibility, prepare configuration, connect the code repository and servers, and deploy to a test environment.
- **Update a project:** Automatically check, build, and deploy code to the test environment after a push, producing a traceable release candidate.
- **Release to production:** After your confirmation and the project's required approvals, deploy the same tested version to production and verify real application behavior.
- **Back up and recover:** Define what data is covered, export it, restore it in an isolated environment, and check the database and backup files.
- **Resume interrupted work:** Let the AI read saved progress and continue from a verifiable checkpoint, preserving completed configuration and exports.

```text
Accounts + servers → Connect pipeline → Test → Approve production → Verify + recover
                            ↑
                  Reuse for later updates
```

The default stack uses Tencent Cloud services: **CNB** hosts code and runs automated jobs, **TCR** stores built application images, and **TAT** sends deployment commands to servers. The AI reads your code to identify the services your project needs and adapt its build and acceptance checks.

## What you need

| Requirement | What to expect |
| --- | --- |
| Project source code | Open the project in your AI coding tool. The AI checks how it builds, runs, and stores data, then identifies anything missing |
| AI coding tool | It must be able to read Skills, read and write project files, run commands, and access Git and network APIs. No specific brand is required; hands-on validation has mainly used Codex |
| Local execution environment | Hands-on validation has used macOS. The full workflow needs a POSIX-like environment, Node.js 22, Python 3.12+, and Git/SSH. Recovery verification also requires Docker accessible through a local Unix socket. The AI checks and prepares dependencies first |
| CNB and Tencent Cloud accounts | You need permission to manage the project and its cloud resources. You complete personal actions such as signing in, identity verification, and verification codes |
| Servers and domains | The full test-and-production setup uses two separate servers. You can start with just a test server and domain, then connect production when it is ready. Existing servers are inspected before use |

The current setup entry point supports containerizable web applications and services using **PostgreSQL 16**, targeting Ubuntu 24.04 / Linux amd64 with Docker Compose and optional Redis 7. **Projects without a database and projects using other databases are not supported by this fixed setup path yet.** The AI checks compatibility and explains the limits first; you do not need to add a database just to deploy. Other operating systems or complex host layouts need assessment; see the [setup guide](references/bootstrap.md). Cloud providers charge their own resource fees.

Your local execution environment is separate from the cloud servers. **Native Windows is not supported by the current full execution entry point.** Linux desktops, WSL, and remote development environments have not completed end-to-end onboarding validation; file permissions, login callbacks, and Docker access need to be checked first. The fixed entry point for creating new image repositories currently supports only Tencent Cloud TCR Personal Edition in Guangzhou. The AI checks whether an existing deployment can be reused.

The AI prefers official sign-in flows or existing initialization credentials. If the default CNB login lacks creation permissions, it prepares the exact options and guides you through creating and securely importing a short-lived initialization token, then continues the automated setup. Required Secret files are still saved through the official website. You do not need to learn commands or permission configuration, or install a browser automation plugin. The AI prepares a terminal with hidden input or an existing secure import feature in your tool. If neither is available, it groups the necessary website actions into a clear handoff.

## Get started

1. Give your AI coding tool the link to this repository and say:
   > Please install or load cnb-devops-skill using a method supported by this tool. Confirm that you can read SKILL.md and tell me where it was actually loaded from.
2. Open your application project's directory in the tool and say:
   > Please use cnb-devops-skill to check whether this project is supported, set up automated deployment to a test environment, and verify access and basic application behavior. When you need information or an action from me, tell me exactly what to do. Wait for my confirmation before releasing to production.
3. Complete the actions the AI requests, then open the delivered test URL and check the application. When you are ready to go live, explicitly request a production release, confirm the specific candidate version, and complete the required approvals.

One person may fill multiple roles if the project's policy permits it. You do not need to write deployment configuration or compile technical evidence yourself. Sensitive values belong only in designated private storage, never in chat or ordinary code repositories.

## What you should receive

- **An accessible environment:** A test or production URL, with the access and application checks actually completed.
- **A traceable release:** Links to the repository, pipeline, and release candidate, plus the version currently running in each environment.
- **Project records you can reuse:** Deployment instructions and current status saved in the project so a later AI session can continue the work.
- **Clear recovery and maintenance information:** Backup scope, actual recovery results or unfinished items, credential expiration dates, and follow-up maintenance tasks.

If only the test environment is set up, delivery covers that scope. Generating files does not mean an application has been deployed. Recovery verification covers only the data explicitly declared and actually tested. Missing prerequisites, failed steps, and unverified areas are recorded separately.

## Use it again

| What you need | What to ask the AI |
| --- | --- |
| Update the project | Please deploy the current changes to the test environment and verify them |
| Resume previous work | Please read the project's deployment and status records, then continue the authorized steps that are still unfinished |
| Add another project | Please use this Skill to set up the same workflow for this project, checking its own accounts, servers, and data scope |
| Release to production | Please prepare the current candidate for production, explain the version and impact, and deploy after completing the project's required approvals |
| Check a completed release | Please perform a read-only check of this release, verify the declared coexistence and acceptance scope, and update the existing project status |

Reusing the workflow across projects means each repository uses the same method and execution tools. To reuse existing servers, you can tell the AI: “Add this project to these two servers and preserve the existing projects.” It first checks capacity, permissions, routing, and data isolation, then uses the [shared-host addition workflow](references/native-caddy-shared.md) where suitable. Test-and-production setup for two projects under the same owner, plus a separate test deployment for a third project, have been verified. Sustained load and isolation between tenants with different trust levels still need validation. Upgrading an existing deployment tool also requires a separate check; rerunning first-time setup must not overwrite it.

## Verification and technical references

The standard workflow has real-project records covering test-and-production releases, application checks, and off-host recovery. See the [verification history](docs/history/README.md) for prerequisites, scope, and unverified areas. The time taken for an individual case is not a delivery promise for a new project.

Official sign-in, CNB private and Secret repository creation, build settings, Tencent Cloud fixed commands, and dedicated identities have undergone [live API validation](docs/history/2026-09-07-api-live-validation.md). Production, recovery, and test closeout use fixed entry points that save evidence and support repeated resumption. Users do not need to compile technical evidence themselves.

The latest [unfamiliar-project onboarding](docs/history/2026-09-11-unfamiliar-project-adoption.md) completed a shared-host test deployment, application checks, and database recovery. Work that still required ad hoc orchestration in that run was then incorporated into the [TCR initialization and test closeout entry points](docs/history/2026-09-11-tcr-test-closeout.md). Read-only rechecks and status synchronization have been verified against existing real resources. Creating fresh resources through the new TCR entry point, automated initialization with a fresh account, and overall speed improvements still need live validation. The AI still issues credentials for the TAT deployment identity by calling the API as documented.

The following documents are primarily for the AI to read as needed; you do not need to study each one. The technical documentation is maintained as one set of files, with mixed Chinese and English content. Both READMEs link to the same files, and the AI explains the current steps in your language:

- [SKILL.md](SKILL.md): Selects the execution entry point for the task.
- [Standard workflow](references/standard-workflow.md): Stage order, responsibilities, and reusable artifacts.
- [Setup guide and complete example](references/bootstrap.md): Configuration generation, host installation, deployment, and recovery.
- [Accounts and API onboarding](references/api-onboarding.md): Official sign-in, automated configuration, and actions that really require the account holder.
- [Image repository initialization](references/tcr-setup.md): How the AI prepares a private TCR repository and push/pull identities, and saves setup progress for resumption.
- [Project adoption](references/project-adoption.md) and [human handoffs](references/human-handoffs.md): Preserve progress and fill only the current gaps.
- [Post-release closeout](references/post-release-closeout.md): Recheck a release without changing remote state, verify declared coexistence, and update local status. Historical release success is recorded separately from current runtime, application, and recovery acceptance results.

## Preview feedback

If you encounter a problem, you can ask the AI:

> Please preserve the current progress and prepare a sanitized report suitable for a GitHub Issue. Include the Skill version, local operating system and AI tool, the stage where work stopped, expected and actual results, and the actions I actually had to perform.

Review the report, then submit it through [GitHub Issues](https://github.com/blacksco0920-dot/cnb-devops-skill/issues) in Chinese or English. Do not upload keys, complete configuration files, backups, or full raw logs; the AI should extract only the necessary error information. See the [Preview release notes](docs/releases/v0.2.0-preview.6.md) for versioning, installation, and maintenance conventions.

## License

This project uses the [MIT License](LICENSE). The source projects' owner has confirmed that the extracted deployment scripts may be distributed with this Skill under MIT; see [source provenance and authorization](assets/cnb-tcr-tat/dependencies/SOURCES.md). Third-party dependencies retain their own licenses; see the [dependency notices](assets/cnb-tcr-tat/dependencies/THIRD_PARTY.md).
