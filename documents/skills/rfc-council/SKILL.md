---
name: rfc-council
description: Unified skill for RFC creation and ticket quality review with multi-agent council deliberation and anti-cousin enforcement.
argument-hint: "[create | review | refine] [PRD-XXXX | RFC-XXXX]"
holon:
  # ============================================================================
  # Contract Definition
  # ============================================================================
  contract:
    input_type: RfcCouncilRequest
    output_type: RfcCouncilResult
    state_type: RfcCouncilProgress

  # ============================================================================
  # Stop Conditions
  # ============================================================================
  stop_conditions:
    # Maximum episodes: RFC work involves multiple phases
    #   - CREATE mode: RFC generation + ticket decomposition ~ 15-20 episodes
    #   - REVIEW mode: 3 review cycles with 7 gates ~ 10-15 episodes
    #   - REFINE mode: Review + remediation ~ 15-20 episodes
    max_episodes: 25

    # Timeout: 30 minutes for complete RFC operations
    timeout_ms: 1800000

    # Budget limits
    budget:
      tokens: 500000
      tool_calls: 500

    # Stall detection
    max_stall_episodes: 5

  # ============================================================================
  # Tool Permissions
  # ============================================================================
  tools:
    - Read         # Read RFCs, tickets, CCP, codebase files
    - Write        # Create RFC YAML files and ticket files
    - Edit         # Modify RFC/ticket files during review
    - Glob         # Find files by pattern
    - Grep         # Search file contents
    - Bash         # Git operations, mkdir
    - Task         # Spawn subagents for council deliberation
---

orientation: "You are an RFC Council agent. Your job is to ensure that engineering tickets derived from RFCs are (a) structurally sound, (b) implementation-ready for other agents, and (c) architecturally compliant (no cousin abstractions). You orchestrate multi-agent deliberations for complex system-wide changes to maintain the North Star vision. Replaces the deprecated `create-rfc` skill."

title: RFC Council & Ticket Review
protocol:
  id: RFC-COUNCIL
  version: 1.0.0
  type: executable_specification
  inputs[2]:
    - MODE_OPTIONAL
    - TARGET_ID
  outputs[2]:
    - FindingsBundle
    - Verdict

variables:
  MODE_OPTIONAL: "$1"
  TARGET_ID: "$2"

references[7]:
  - path: references/rfc-council-workflow.md
    purpose: "Primary decision tree for mode selection and input validation."
  - path: references/create-mode.md
    purpose: "Logic for generating RFC and tickets from PRD."
  - path: references/review-mode.md
    purpose: "Logic for formal ticket review and depth computation."
  - path: references/refine-mode.md
    purpose: "Logic for iterative review and remediation."
  - path: references/REVIEW_RUBRIC.md
    purpose: "Formal gate definitions and evidence contracts."
  - path: references/FINDING_CATEGORIES.md
    purpose: "Deterministic finding taxonomy and severity rules."
  - path: references/COUNCIL_PROTOCOL.md
    purpose: "Multi-agent deliberation protocol for COUNCIL reviews."
  - path: references/commands.md
    purpose: "CLI command reference."

decision_tree:
  entrypoint: WORKFLOW
  nodes[1]:
    - id: WORKFLOW
      action: invoke_reference
      reference: references/rfc-council-workflow.md

## Verdict Rules

- **APPROVED**: All gates passed, zero BLOCKER/MAJOR findings.
- **APPROVED_WITH_REMEDIATION**: All gates passed, 1-3 MAJOR findings with fixes.
- **REJECTED**: Any gate failed OR >3 MAJOR findings.
- **NEEDS_ADJUDICATION**: Council deadlocked on a critical finding or confidence is LOW.

## Success Metrics

- **First-pass success rate**: >=80% (Tickets merged without rework)
- **Rework rate**: <=15% (Tickets requiring revision)
- **Anti-cousin compliance**: >=95% (Tickets with no COUSIN findings)
- **Dependency accuracy**: >=90% (Tickets without blocked merges)

## North Star Alignment

This protocol directly serves **Phase 1 (Recursive Self-Improvement)** by:
- Enabling agent autonomy through implementable tickets.
- Preventing architectural debt via anti-cousin discipline.
- Improving first-pass success rate to reduce human intervention.
- Ensuring atomic tickets enable parallel agent execution.