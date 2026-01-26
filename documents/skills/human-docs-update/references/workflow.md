title: Human Docs Update Workflow

decision_tree:
  entrypoint: VALIDATE_AND_NORMALIZE
  nodes[6]:
    - id: VALIDATE_AND_NORMALIZE
      purpose: "Validate we're in a git repo and normalize the starting state."
      steps[4]:
        - id: CHECK_GIT_REPO
          action: |
            Verify we're in a git repository:
            ```bash
            git rev-parse --is-inside-work-tree
            ```
            If not a git repo, HALT with error.

        - id: INVOKE_GIT_NORMALIZE
          action: invoke_reference
          reference: references/git-normalize.md

        - id: CHECK_CHANGES_EXIST
          action: |
            Verify there are changes to process:
            ```bash
            git status --porcelain
            ```
            If no output (no changes), HALT with message "No changes to commit."

        - id: ENSURE_FEATURE_BRANCH
          action: |
            Check current branch:
            ```bash
            git branch --show-current
            ```
            If on `main` or `master`:
            - If BRANCH_NAME_OPTIONAL provided, create and switch to it
            - Otherwise, derive branch name from changed files (e.g., `docs/update-<date>`)
            ```bash
            git checkout -b <branch-name>
            ```
      decisions[1]:
        - id: PROCEED_TO_CHECKS
          if: "changes exist and on feature branch"
          then:
            next_node: RUN_LOCAL_CHECKS

    - id: RUN_LOCAL_CHECKS
      purpose: "Run formatting and linting checks before committing."
      steps[3]:
        - id: RUN_PRECOMMIT
          action: |
            Run pre-commit hooks on all files:
            ```bash
            pre-commit run --all-files
            ```
            If pre-commit not installed, skip this step.
            Note: pre-commit may auto-fix some issues (trailing whitespace, etc.)

        - id: CHECK_MARKDOWN_LINT
          action: |
            If markdownlint available, run on changed markdown files:
            ```bash
            markdownlint --fix "**/*.md"
            ```
            Auto-fixes will be staged in the next step.

        - id: CHECK_YAML_VALID
          action: |
            Validate any changed YAML files:
            ```bash
            check-yaml <changed-yaml-files>
            ```
            If validation fails, report errors and HALT.
      decisions[1]:
        - id: PROCEED_TO_STAGE
          if: "checks pass or only auto-fixable issues"
          then:
            next_node: STAGE_AND_COMMIT

    - id: STAGE_AND_COMMIT
      purpose: "Stage all changes and create a conventional commit."
      steps[4]:
        - id: IDENTIFY_CHANGES
          action: |
            List all changes for commit message context:
            ```bash
            git status --porcelain
            git diff --stat
            ```
            Categorize changes by type (modified, added, deleted).

        - id: STAGE_ALL_CHANGES
          action: |
            Stage all modified, deleted, and untracked files:
            ```bash
            git add <specific-files>
            ```
            Prefer explicit file paths over `git add -A` to avoid accidents.

        - id: COMPOSE_COMMIT_MESSAGE
          action: |
            Create a conventional commit message:
            - Analyze staged changes to determine type (feat, fix, docs, refactor)
            - For documentation changes, prefer `docs:` or `feat:` prefix
            - Include brief summary of what changed
            - Add `Co-Authored-By: Claude <noreply@anthropic.com>` footer

        - id: CREATE_COMMIT
          action: |
            Create the commit:
            ```bash
            git commit -m "<message>"
            ```
            If commit fails (e.g., hooks reject), fix issues and retry.
      decisions[1]:
        - id: PROCEED_TO_SYNC
          if: "commit created successfully"
          then:
            next_node: SYNC_WITH_REMOTE

    - id: SYNC_WITH_REMOTE
      purpose: "Fetch latest from origin/main and rebase."
      steps[3]:
        - id: FETCH_ORIGIN
          action: |
            Fetch latest from origin:
            ```bash
            git fetch origin main
            ```

        - id: REBASE_ON_MAIN
          action: |
            Rebase current branch on origin/main:
            ```bash
            git rebase origin/main
            ```
            If conflicts occur:
            - Attempt to resolve automatically for trivial cases
            - Otherwise, HALT and report conflicts for manual resolution

        - id: VERIFY_REBASE
          action: |
            Confirm rebase succeeded:
            ```bash
            git log --oneline origin/main..HEAD
            ```
            Should show our commit(s) ahead of main.
      decisions[1]:
        - id: PROCEED_TO_PUSH
          if: "rebase successful"
          then:
            next_node: PUSH_AND_CREATE_PR

    - id: PUSH_AND_CREATE_PR
      purpose: "Push branch, create PR, request reviews, and enable auto-merge using xtask."
      steps[3]:
        - id: RUN_XTASK_PUSH
          action: |
            Use xtask to handle push, PR creation, reviews, and auto-merge:
            ```bash
            cargo xtask push
            ```
            This command:
            - Pushes current branch to origin
            - Creates PR if needed (or updates existing)
            - Requests AI code-quality and security reviews
            - Enables squash auto-merge

            If xtask push fails, fall back to manual steps (see MANUAL_FALLBACK).

        - id: CAPTURE_PR_URL
          action: |
            Get PR URL for output:
            ```bash
            gh pr view --json url -q .url
            ```

        - id: REPORT_SUCCESS
          action: |
            Output final status:
            - PR URL
            - Review status (requested via xtask)
            - Auto-merge status (enabled via xtask)
            - Any warnings from xtask output
      decisions[2]:
        - id: WORKFLOW_COMPLETE
          if: "xtask push succeeded"
          then:
            verdict: SUCCESS
            output: PR_URL
        - id: MANUAL_FALLBACK
          if: "xtask push failed"
          then:
            next_node: MANUAL_PR_WORKFLOW

    - id: MANUAL_PR_WORKFLOW
      purpose: "Fallback manual PR workflow if xtask unavailable."
      steps[4]:
        - id: PUSH_BRANCH
          action: |
            Push branch to origin with tracking:
            ```bash
            git push -u origin <branch-name>
            ```
            If branch already exists on remote, use `--force-with-lease` after rebase.

        - id: CREATE_PR
          action: |
            Create pull request with descriptive content:
            ```bash
            gh pr create --title "<title>" --body "$(cat <<'EOF'
            ## Summary
            <bullet points>

            ## Test plan
            - [ ] Verification steps

            🤖 Generated with [Claude Code](https://claude.com/claude-code)
            EOF
            )"
            ```

        - id: REQUEST_REVIEWS
          action: |
            Request AI reviews (may fail if not collaborators):
            ```bash
            gh pr edit --add-reviewer ai-review/code-quality,ai-review/security
            ```

        - id: ENABLE_AUTO_MERGE
          action: |
            Enable squash auto-merge:
            ```bash
            gh pr merge --auto --squash
            ```
      decisions[1]:
        - id: MANUAL_COMPLETE
          if: "PR created"
          then:
            verdict: SUCCESS
            output: PR_URL
