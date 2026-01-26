title: Git State Normalization

decision_tree:
  entrypoint: ASSESS_STATE
  nodes[4]:
    - id: ASSESS_STATE
      purpose: "Assess current git state and determine normalization actions."
      steps[5]:
        - id: CHECK_UNCOMMITTED_CHANGES
          action: |
            Check for uncommitted changes:
            ```bash
            git status --porcelain
            ```
            Categorize output:
            - `M ` or ` M` = modified files
            - `A ` = staged new files
            - `D ` or ` D` = deleted files
            - `??` = untracked files
            - `UU` = merge conflicts

        - id: CHECK_MERGE_IN_PROGRESS
          action: |
            Check for in-progress merge:
            ```bash
            git merge HEAD 2>&1 | grep -q "Already up to date" || test -f .git/MERGE_HEAD
            ```
            If MERGE_HEAD exists, we're in a merge state.

        - id: CHECK_REBASE_IN_PROGRESS
          action: |
            Check for in-progress rebase:
            ```bash
            test -d .git/rebase-merge || test -d .git/rebase-apply
            ```
            If either directory exists, we're in a rebase state.

        - id: CHECK_REMOTE_TRACKING
          action: |
            Check if branch tracks a remote:
            ```bash
            git rev-parse --abbrev-ref --symbolic-full-name @{u} 2>/dev/null
            ```
            If fails, branch has no upstream.

        - id: CHECK_DIVERGENCE
          action: |
            Check if branch has diverged from remote:
            ```bash
            git fetch origin
            git rev-list --left-right --count HEAD...@{u} 2>/dev/null
            ```
            Output: `<ahead>\t<behind>`
      decisions[4]:
        - id: HANDLE_CONFLICTS
          if: "merge conflicts present (UU files)"
          then:
            next_node: RESOLVE_CONFLICTS
        - id: HANDLE_REBASE
          if: "rebase in progress"
          then:
            next_node: HANDLE_REBASE_STATE
        - id: HANDLE_MERGE
          if: "merge in progress"
          then:
            next_node: HANDLE_MERGE_STATE
        - id: PROCEED_NORMAL
          if: "clean or just uncommitted changes"
          then:
            next_node: NORMALIZE_BRANCH

    - id: RESOLVE_CONFLICTS
      purpose: "Handle merge/rebase conflicts before proceeding."
      steps[2]:
        - id: LIST_CONFLICTS
          action: |
            List conflicted files:
            ```bash
            git diff --name-only --diff-filter=U
            ```

        - id: HALT_FOR_CONFLICTS
          action: |
            HALT with message:
            "Cannot proceed: merge conflicts exist in the following files:
            <list of files>

            Please resolve conflicts manually, then re-run this workflow."
      decisions[1]:
        - id: CONFLICTS_HALT
          if: "always"
          then:
            verdict: BLOCKED
            reason: "Unresolved merge conflicts"

    - id: HANDLE_REBASE_STATE
      purpose: "Handle in-progress rebase."
      steps[2]:
        - id: OFFER_ABORT
          action: |
            Check rebase state:
            ```bash
            git status
            ```
            If rebase has conflicts, HALT for manual resolution.
            If rebase is clean (just needs continue), continue it.

        - id: CONTINUE_OR_ABORT
          action: |
            If no conflicts:
            ```bash
            git rebase --continue
            ```
            If conflicts present, HALT with instructions.
      decisions[2]:
        - id: REBASE_CONTINUED
          if: "rebase continued successfully"
          then:
            next_node: NORMALIZE_BRANCH
        - id: REBASE_BLOCKED
          if: "rebase has conflicts"
          then:
            verdict: BLOCKED
            reason: "Rebase conflicts require manual resolution"

    - id: HANDLE_MERGE_STATE
      purpose: "Handle in-progress merge."
      steps[2]:
        - id: CHECK_MERGE_CONFLICTS
          action: |
            Check if merge has conflicts:
            ```bash
            git diff --name-only --diff-filter=U
            ```

        - id: COMPLETE_OR_ABORT
          action: |
            If no conflicts, commit the merge:
            ```bash
            git commit --no-edit
            ```
            If conflicts present, HALT with instructions.
      decisions[2]:
        - id: MERGE_COMPLETED
          if: "merge committed"
          then:
            next_node: NORMALIZE_BRANCH
        - id: MERGE_BLOCKED
          if: "merge has conflicts"
          then:
            verdict: BLOCKED
            reason: "Merge conflicts require manual resolution"

    - id: NORMALIZE_BRANCH
      purpose: "Ensure branch is ready for new work."
      steps[4]:
        - id: STASH_IF_NEEDED
          action: |
            If there are changes AND we need to switch branches:
            ```bash
            git stash push -m "human-docs-update: auto-stash"
            ```
            Track that we stashed so we can pop later.

        - id: FETCH_LATEST
          action: |
            Fetch latest from origin:
            ```bash
            git fetch origin
            ```

        - id: CHECK_MAIN_DIVERGENCE
          action: |
            If on feature branch, check divergence from main:
            ```bash
            git rev-list --count HEAD..origin/main
            ```
            If significantly behind (>50 commits), warn user.

        - id: POP_STASH_IF_NEEDED
          action: |
            If we stashed earlier:
            ```bash
            git stash pop
            ```
            If pop fails (conflicts), HALT for manual resolution.
      decisions[1]:
        - id: NORMALIZED
          if: "branch normalized successfully"
          then:
            verdict: READY
            state: "Git state normalized, ready to proceed"
