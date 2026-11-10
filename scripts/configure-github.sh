#!/usr/bin/env bash
# Applies the repository settings, rulesets, Actions policy and release
# environment this project depends on. It is idempotent, so it can be re-run
# against an existing repository to correct drift, and it is the single record
# of what those settings are. docs/repository-security.md explains the reasoning.
#
# Usage:  scripts/configure-github.sh [owner/repo]
#
# It needs the GitHub CLI authenticated as an organisation owner, with the
# `repo` scope. Some settings (secret scanning, push protection, private
# vulnerability reporting, fork approval) are only offered by GitHub on public
# repositories or with Advanced Security, so each call is attempted and reported
# rather than aborting the run.

set -uo pipefail

REPO="${1:-Open-Transaction-Layer/otl-sdk}"
ORG="${REPO%%/*}"
TEAM="maintainers"
API="repos/${REPO}"
failed=0

say() { printf '\n== %s\n' "$1"; }
api() { # api METHOD PATH [json-body]; reports success or the failure reason
  local method="$1" path="$2" body="${3:-}" out
  if [ -n "$body" ]; then
    out=$(printf '%s' "$body" | gh api -X "$method" "$path" --input - 2>&1)
  else
    out=$(gh api -X "$method" "$path" 2>&1)
  fi
  if [ $? -eq 0 ]; then echo "ok    $method $path"; else
    echo "FAIL  $method $path: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"; failed=1
  fi
}

say "Repository"
api PATCH "$API" '{
  "homepage": "https://www.otl.network/",
  "has_issues": true, "has_wiki": false, "has_projects": false, "has_discussions": false,
  "allow_squash_merge": true, "allow_merge_commit": false, "allow_rebase_merge": false,
  "allow_auto_merge": false, "allow_update_branch": true,
  "delete_branch_on_merge": true,
  "squash_merge_commit_title": "PR_TITLE", "squash_merge_commit_message": "PR_BODY",
  "web_commit_signoff_required": false
}'

say "Security features"
api PUT "$API/vulnerability-alerts"
api PUT "$API/automated-security-fixes"
api PATCH "$API" '{"security_and_analysis": {
  "secret_scanning": {"status": "enabled"},
  "secret_scanning_push_protection": {"status": "enabled"},
  "secret_scanning_non_provider_patterns": {"status": "enabled"},
  "secret_scanning_validity_checks": {"status": "enabled"}
}}'
api PUT "$API/private-vulnerability-reporting"

say "Team access"
api PUT "orgs/$ORG/teams/$TEAM/repos/$REPO" '{"permission": "push"}'

say "Actions policy"
api PUT "$API/actions/permissions" '{"enabled": true, "allowed_actions": "selected", "sha_pinning_required": true}'
api PUT "$API/actions/permissions/selected-actions" '{
  "github_owned_allowed": true,
  "verified_allowed": false,
  "patterns_allowed": ["changesets/action@*", "zizmorcore/zizmor-action@*", "ossf/scorecard-action@*"]
}'
api PUT "$API/actions/permissions/workflow" '{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false}'
api PUT "$API/actions/permissions/fork-pr-contributor-approval" '{"approval_policy": "all_external_contributors"}'

say "Rulesets"
# A ruleset is matched by name so that re-running updates it instead of
# creating a duplicate.
upsert_ruleset() { # upsert_ruleset NAME JSON
  local name="$1" body="$2" id
  id=$(gh api "$API/rulesets" --jq ".[] | select(.name == \"$name\") | .id" 2>/dev/null | head -n1)
  if [ -n "$id" ]; then api PUT "$API/rulesets/$id" "$body"; else api POST "$API/rulesets" "$body"; fi
}

# No bypass actors: administrators go through the same pull request, review and
# status-check path as everyone else.
upsert_ruleset "Protect main" '{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {"type": "required_signatures"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 1,
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": true,
      "require_last_push_approval": true,
      "required_review_thread_resolution": true,
      "allowed_merge_methods": ["squash"]
    }},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": true,
      "do_not_enforce_on_create": false,
      "required_status_checks": [
        {"context": "check (Node 22.12)"},
        {"context": "check (Node 24)"},
        {"context": "packaging"},
        {"context": "audit"},
        {"context": "zizmor"},
        {"context": "CodeQL"},
        {"context": "dependency-review"}
      ]
    }}
  ]
}'

# Release tags cannot be moved or deleted. Creation stays open because the
# release workflow creates them.
upsert_ruleset "Protect tags" '{
  "name": "Protect tags",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
  "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}]
}'

say "Release environment"
team_id=$(gh api "orgs/$ORG/teams/$TEAM" --jq .id 2>/dev/null)
api PUT "$API/environments/release" "{
  \"wait_timer\": 0,
  \"prevent_self_review\": false,
  \"reviewers\": [{\"type\": \"Team\", \"id\": ${team_id:-0}}],
  \"deployment_branch_policy\": {\"protected_branches\": false, \"custom_branch_policies\": true}
}"
api POST "$API/environments/release/deployment-branch-policies" '{"name": "main", "type": "branch"}'

say "Done"
cat <<EOF
Secrets are never stored in this repository. Add the npm publish token to the
release environment yourself, which keeps it out of every other job:

  gh secret set NPM_TOKEN --env release --repo $REPO

EOF
exit "$failed"
