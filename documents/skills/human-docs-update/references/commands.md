title: Human Docs Update Command Reference

commands[10]:
  - name: check-git-state
    command: "git status --porcelain"
    purpose: "Show all uncommitted changes in machine-readable format."

  - name: check-branch
    command: "git branch --show-current"
    purpose: "Show current branch name."

  - name: create-feature-branch
    command: "git checkout -b <branch-name>"
    purpose: "Create and switch to a new feature branch."

  - name: run-precommit
    command: "pre-commit run --all-files"
    purpose: "Run all pre-commit hooks (formatting, linting, etc.)."

  - name: stage-files
    command: "git add <file1> <file2> ..."
    purpose: "Stage specific files for commit. Prefer explicit paths over -A."

  - name: commit-with-coauthor
    command: |
      git commit -m "$(cat <<'EOF'
      <type>: <description>

      Co-Authored-By: Claude <noreply@anthropic.com>
      EOF
      )"
    purpose: "Create commit with conventional message and co-author footer."

  - name: sync-with-main
    command: "git fetch origin main && git rebase origin/main"
    purpose: "Fetch latest main and rebase current branch on it."

  - name: push-and-pr
    command: "cargo xtask push"
    purpose: "Push, create/update PR, run AI reviews, enable auto-merge."

  - name: push-force-review
    command: "cargo xtask push --force-review"
    purpose: "Force re-run reviews after addressing feedback."

  - name: get-pr-url
    command: "gh pr view --json url -q .url"
    purpose: "Get the URL of the current PR."
