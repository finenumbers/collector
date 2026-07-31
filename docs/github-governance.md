# GitHub repository governance

This document defines the repository settings and operating procedure for the
default branch, release tags, dependency updates, and security features. Apply
these controls through GitHub repository rulesets and settings; workflow files
do not enforce repository settings by themselves.

## Default branch protection

Protect `main` with a branch ruleset that:

- requires every change to arrive through a pull request;
- requires zero approving reviews, so a pull request may be merged after all
  automated checks pass;
- requires these CI checks from `.github/workflows/ci.yml`:
  - `Go test and vet`;
  - `Frontend lint and build`;
  - `Container and Portainer stack`;
  - `Dependency review` (pull requests only);
- also requires GitHub code scanning (CodeQL) when enabled for the repository:
  - `Analyze (go)`;
  - `Analyze (actions)`;
  - `Analyze (javascript-typescript)`;
  - aggregate `CodeQL`, which fails when a pull request introduces an alert;
- requires the branch to be up to date before merging;
- blocks force pushes and branch deletion;
- does not allow direct pushes or bypasses, including for administrators.

Merge only after all required checks pass. Repository administrators should use
the same pull-request path as other contributors for routine and emergency
changes.

## Release tag protection

Protect tags matching `v*` with a tag ruleset. Release tags are immutable:
creation is restricted to maintainers following the release procedure, while
updates, force pushes, and deletion are blocked without bypass exceptions.
Never reuse a version after publishing it; issue a new patch version instead.

## Dependency updates

Enable Dependabot version updates and security updates. Routine compatible
updates follow the normal pull-request and required-check process. Major-version
updates require explicit maintainer review of release notes, migration guidance,
breaking API or configuration changes, and rollback impact before merge.

CI dependency review fails pull requests that introduce dependencies with
moderate-or-higher known vulnerabilities. No license allowlist or denylist is
configured; license policy changes require a documented legal or project-policy
decision rather than relying on action defaults.

## Security settings

Enable GitHub dependency graph, Dependabot alerts, Dependabot security updates,
secret scanning, secret-scanning push protection, and private vulnerability
reporting where available. Keep workflow permissions read-only by default and
grant write permissions only to the release workflow jobs that publish artifacts
and attestations. Require immutable commit SHAs for every workflow action and
allow only GitHub-owned actions plus the explicitly selected `docker/*`
publisher namespace.

Investigate security alerts promptly. Remediation changes still use a pull
request and required checks; coordinate disclosure privately when an issue is
not yet public.

## Release procedure

1. Merge the release-ready changes into `main` through a pull request and verify
   all required checks pass.
2. Choose the next semantic version and confirm that its `vMAJOR.MINOR.PATCH` tag
   does not already exist.
3. Create an annotated tag from the intended commit on `main`, then push that
   new tag once.
4. The `Release` workflow builds and pushes the multi-architecture GHCR image,
   publishes provenance and SBOM data, and creates the GitHub release with
   generated notes.
5. Verify the workflow result, release notes, image tags and digest, and build
   attestation. If correction is necessary, fix it on `main` and publish a new
   patch version; do not move or delete the published tag.
