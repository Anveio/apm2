## Security Review: PASS

This PR implements the `ListFiles` and `Search` tools for FAC v0 reviewer navigation. A critical path traversal vulnerability was identified during code review and **remediated in commit 4efea0d**. The final implementation correctly enforces sandboxing, resource bounds, and context firewall rules.

### SCP Determination
**YES**. The changes affect:
- **FILESYSTEM**: Direct filesystem access via `fs.rs`.
- **POLICY_GATES**: Context firewall enforcement for new tool classes.
- **NETWORK_IPC**: New proto messages.

### Markov Blanket Analysis
- **Inputs**: `ListFiles` (path, pattern), `Search` (query, scope).
- **Validation**:
    - `validate_path`: Enforces sandbox rooting and bans `..`.
    - `list_files`: Explicitly checks `pattern` for `..` (Added in fix).
    - `search`: Explicitly checks `scope` for `..`.
    - `BrokerToolRequest`: Validates lengths (`MAX_LIST_FILES_PATTERN_LEN`, `MAX_SEARCH_QUERY_LEN`).
- **Outputs**: Truncated text/file lists.
- **Failure Behavior**: Fail-closed (returns error on traversal attempt or firewall miss).

### **POSITIVE OBSERVATIONS (PASS)**
1.  **Remediation of Traversal**: The initial implementation of `list_files` vulnerable to `pattern="../secret"` was fixed by adding an explicit check: `if req.pattern.contains("..") { return Err(...) }`. This matches the defense-in-depth pattern used elsewhere.
2.  **Resource Bounds**: Strict limits on `max_entries` (2000), `max_bytes` (65536), and `max_lines` (2000) prevent DoS attacks via large outputs or deep directory trees.
3.  **Context Firewall Integration**: `ListFiles` and `Search` are correctly classified as read operations and gated by `validate_read`, ensuring reviewers can only navigate paths allowed by the capability manifest.
4.  **Allowlist Enforcement**: The capability manifest allowlists (topic, cas_hash) implemented in TCK-00314 (included in this branch) provide granular access control for session operations.

### Assurance Case
- **Claim**: Navigation tools cannot access files outside the workspace.
    - **Argument**: Both `path` and `pattern`/`scope` inputs are validated to ensure they do not contain traversal sequences and resolve to paths within the workspace root.
    - **Evidence**: `crates/apm2-core/src/tool/fs.rs` `list_files` and `search` methods, verified by `test_list_files_traversal_blocked`.
- **Claim**: Navigation operations cannot cause resource exhaustion.
    - **Argument**: Output size and item counts are strictly bounded by constants (`MAX_SEARCH_BYTES`, `MAX_LIST_FILES_ENTRIES`).
    - **Evidence**: `crates/apm2-core/src/tool/fs.rs` loop termination conditions.

---
Reviewed commit: 4efea0dc11fb8cb99cd4997fcfb86464320869c4
