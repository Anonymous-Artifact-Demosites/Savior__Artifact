# SAVIOR: Systematic Analysis of Vulnerabilities in Integrated OAuth Relying Parties

This repository contains the source code and accompanying artifacts for the paper *"The Tower of Babel: Systematically Analyzing Account Management Vulnerabilities in Web OAuth Integration"*.

## 1. Repository Contents

This repository includes:

- The core source code of SAVIOR's three-layer architecture.
- The complete intent library and the per-vector task compositions for all 7 attack vectors (`configs/intent_library.yaml` and `configs/task_compositions.yaml`), i.e., the exact instructions composed for the LLM.
- The invariant rule library (`configs/invariants.yaml`).
- Task entry scripts.
- Two sanitized real-world example runs (the Pinterest motivation case and one T2 case study).

## 2. Architecture

SAVIOR implements the three-layer architecture described in Section 5.2 of the paper. Each layer has a single, clearly defined responsibility. `semantic_navigator/tasks/` contains the task entry scripts that connect the three layers for each attack vector.

```text
+----------------------------------------------------------+
|  Semantic Navigator       semantic_navigator/            |
|  - Task entry points      tasks/t1_step1.py, ...         |
|  - Prompt assembly        task_orchestrator.py           |
|  - Iterative strategy     iterative_executor.py          |
|  - Intent library         configs/intent_library.yaml    |
|  - Task compositions      configs/task_compositions.yaml |
+----------------------------------------------------------+
|  Browser Interactor       browser_interactor/            |
|  - LLM-driven execution   claude_runner.py               |
|  - URL pre-filtering      url_prefilter.py               |
|  - CAPTCHA handling       captcha_solver.py + handler.py |
+----------------------------------------------------------+
|  State Auditor            state_auditor/                 |
|  - Invariant rule engine  invariants.py                  |
|  - Output parsing         verdict_parser.py              |
|  - Dual-path cross-check  auditor.py                     |
|  - Report generation      evidence_compiler.py           |
+----------------------------------------------------------+
```

**Semantic Navigator** is the cognitive core (Section 5.2.2). It performs intent-based semantic abstraction, compositional prompt construction, and multistage task orchestration. Given a task identifier and user-provided variables (URL, credentials, and task-specific parameters), it assembles a fully instantiated prompt and defines the iterative execution strategy. It organizes 19 reusable intents into an intent library, each capturing a semantic UI goal independent of surface presentation (for example, `PERFORM_OAUTH_LOGIN`). Intents are classified as either directive (system-level instructions such as browser rules and CAPTCHA delegation) or interaction (semantic UI goals). Each attack vector is defined as a task composition: an ordered sequence of intent references with task-specific variables, so the same intent (e.g., `PERFORM_OAUTH_LOGIN`, reused across T1, T2, T5, and T6) can serve multiple vectors.

**Browser Interactor** provides the controlled execution environment (Section 5.2.1). It manages browser instance creation, URL preprocessing, and command execution, and it carries out the audit through Claude Code + Playwright MCP, returning raw model output. When available, the output includes structured `<observations>`, `<verdict>`, and `<evidence>` blocks.

**State Auditor** takes the raw output, parses the structured blocks, evaluates YAML-defined invariants over the observations, reconciles the rule path and the LLM path, and produces the final report-ready artifacts (Section 5.2.3).

### Algorithm 1 Function Mapping

Each function in Algorithm 1 of the paper maps to a concrete implementation:

| Algorithm 1 Function | Implementation |
| --- | --- |
| CONSTRUCTPROMPT | `semantic_navigator/task_orchestrator.py::construct_prompt()` |
| LLMORACLE | `browser_interactor/claude_runner.py::run_claude()` |
| PARSEOUTPUT | `state_auditor/verdict_parser.py::parse_output()` |
| EVALPRECONDITIONS | Encoded as N/A verdict rules in `configs/invariants.yaml` and evaluated by `state_auditor/invariants.py::evaluate_invariants()` |
| RULEENGINE | `state_auditor/invariants.py::evaluate_invariants()` |
| CROSSCHECK | `state_auditor/auditor.py::cross_check()` |
| COMPILEREPORT | `state_auditor/evidence_compiler.py::compile_*_report()` |

## 3. Model and Configuration

The experiments reported in the paper use Claude Sonnet 4.5 through the Claude Code CLI with default parameters (no temperature sweep and no custom sampling). The released code invokes the installed Claude Code CLI and uses the model configured in that environment unless the researcher overrides it. The paper additionally reports a cross-model comparison (Section 6.5) in which Claude Sonnet 4.5 achieved the highest precision in semantic state adjudication, particularly for T6.

Browser automation is provided by the Playwright MCP server, which supports programmatic control of Chrome, including:

- Page navigation.
- Element interaction.
- Form filling.
- Cross-tab session management, for example switching between the target website and Gmail to complete out-of-band email verification.

End-to-end live-site execution additionally requires a local Claude Code setup, Playwright MCP, researcher-controlled test accounts, and handling of site-specific verification challenges.

SAVIOR separates semantic execution from invariant-driven verification:

- The **Semantic Navigator** uses LLM-based semantic UI understanding to navigate and operate across heterogeneous web interfaces. For example, it can recognize that "unlink", "disconnect", and "remove account" correspond to the same authorization-revocation intent, and complete OAuth handshakes, email verification, and identifier collection without site-specific selectors or custom scripts. The **Browser Interactor** executes these browser operations through Claude Code and Playwright MCP.
- The **State Auditor** independently evaluates the collected observations against the formal security invariants defined in `invariants.yaml`, and reconciles the rule-path result with the LLM verdict through a cross-check mechanism.

As a result, vulnerability decisions are grounded in both semantic observations and formal property verification.

## 4. Detection Pipeline

For each attack vector Tk (k = 1..7):

### 1. Prompt Construction

`task_orchestrator.py` assembles each audit prompt compositionally from three sources:

- The task composition for Tk in `configs/task_compositions.yaml`, which lists the ordered intents to execute.
- The intent definitions in `configs/intent_library.yaml`, whose prompt fragments are concatenated per the composition.
- The security invariants in `configs/invariants.yaml`, which define the properties that the State Auditor will verify.

The final prompt includes three parts:

- An invariant context block (`_build_auditor_context()`) telling the LLM which security properties matter and what observations should be collected.
- A step-by-step audit procedure (the concatenated intent fragments) covering, for example, opening the target URL, locating login or registration pages, performing OAuth flows, and collecting identifiers.
- A structured output schema defining the JSON fields inside `<observations>` for independent rule evaluation by the State Auditor.

As a concrete illustration, the T6 task composition (abbreviated) is the intent sequence `CHECK_OAUTH_AVAILABILITY -> PERFORM_OAUTH_LOGIN(A) -> CHANGE_IDENTIFIER(A->B) -> COMPLETE_EMAIL_VERIF -> PERFORM_OAUTH_LOGIN(B) -> PERFORM_OAUTH_LOGIN(A) -> COMPARE_IDENTIFIERS`, with the auditor context injecting the Q6 invariant: after an identifier update, IdP bindings associated with the previous identifier must no longer grant access.

The complete intent library and the per-vector task compositions for all 7 attack vectors are included under `configs/`.

### 2. Browser Execution

`claude_runner.py` invokes the Claude CLI via subprocess with:

- A default timeout of 600 seconds.
- A default retry count of 2, retrying when Claude exits non-zero with empty output.

The LLM performs the audit through Playwright and returns three structured blocks:

- `<observations>` containing per-step booleans and collected identifiers.
- `<verdict>` containing STATUS / CONFIDENCE / REASONING.
- `<evidence>` containing vulnerability-analysis details.

When a CAPTCHA appears, the Semantic Navigator suspends execution and delegates to a configurable CAPTCHA handler (`handler.py`). The handler is backend-agnostic and defaults to a human-in-the-loop mode in which the operator completes the challenge manually, after which the agent resumes autonomously. The artifact ships only the handler interface and does **not** bundle any automated CAPTCHA-solving implementation; researchers may plug in self-hosted solvers or browser-mediated manual handlers in accordance with their institutional ethics policies. CAPTCHA encounters are recorded in the structured observations or step log when reported by the run.

During browser execution, the LLM invokes `handler.py` via subprocess when it encounters a CAPTCHA challenge.

### 3. Output Parsing

`verdict_parser.py::parse_output()` extracts structured blocks from the raw LLM output.

It implements a three-level fallback chain:

- **Level 1** parses the XML-tagged blocks `<observations>`, `<verdict>`, and `<evidence>`.
- **Level 2** uses task-specific regexes to extract fallback-format status values when XML is absent.
- **Level 3** returns `None` while preserving the raw output for manual inspection if all parsing fails.

JSON parse errors are recorded in `observations_error` instead of being raised.

### 4. Dual-Path Verification

The system computes two separated verdict paths for the same run:

- **Rule path** - `invariants.py` recursively evaluates YAML-defined security invariants over `observations.task_specific`.
- **LLM path** - uses the STATUS extracted from `<verdict>`.

These two paths are separated computationally: the rule engine deterministically evaluates the structured observations, while the LLM separately reports its own status verdict.

### 5. Cross-check

`auditor.py::cross_check()` merges the two verdict paths. These outcomes feed the final Algorithm 1 verdict (VULN / SAFE / UNCERTAIN / N/A):

- `verified` - both paths agree (high confidence).
- `uncertain` - the paths conflict (requires manual review).
- `rule_only` / `llm_only` - only one path produced a result.
- `llm_only_na` - the LLM reports a task-specific N/A status while the rule path is unavailable or degraded.
- `unavailable` - neither path produced a result.

The core outcomes reported in Algorithm 1 are `verified`, `uncertain`, and `N/A`. The additional categories (`rule_only`, `llm_only`, `llm_only_na`, and `unavailable`) are implementation-level fallback states for cases where one or both paths fail to produce a usable output. They are retained in logs for diagnosis and conservatively treated as requiring manual review or non-verified status in the final verdict.

### 6. Iterative Execution

`iterative_executor.py` implements the iterative execution strategy described in Section 6.2 of the paper. It typically runs each target 5-10 times to reduce variance from LLM-driven browser interaction.

The aggregation logic includes:

- **Early exit** - stop immediately once a `source == verified` VULN is found.
- **Weak-signal handling** - e.g., task-specific weak or doubt statuses are retained in the iteration history instead of being flattened into `SAFE`.
- **Majority vote** - if no VULN is found, SAFE is aggregated by majority.
- **Full history retention** - preserve per-iteration `status/source/confidence` for analysis.

## 5. Invariants and Mapping to Table 1

Each invariant in `configs/invariants.yaml` encodes one vulnerability primitive Q from Table 1 of the paper as a mechanically evaluable condition. The `reference` field explicitly links each invariant to its corresponding Q number.

| Task | Primary Q | Invariant | Security property |
| --- | --- | --- | --- |
| T1_STEP1 | Q1 | INV_T1_1 | Registration without identifier ownership verification |
| T1_STEP2 | Q4 | INV_T1_2 | OAuth silently links to an unverified first-party account |
| T2 | Q2, Q3 | INV_T2_1 | Verification signal not bound to session; victim's verification finalizes the attacker's pending registration |
| T3 | Q5 | INV_T3_1 | Identifier change does not require old-identifier verification |
| T4 | Q7 | INV_T4_1 | Session persists after credential change |
| T5 | Q8 | INV_T5_1 | IdP binding or unbinding operations proceed without reauthentication |
| T6 | Q6 | INV_T6_1 | Old IdP binding remains valid after identifier update |
| T7 | Q3 | INV_T7_1 | Premature identifier lock enables registration DoS |

The rule engine supports `all_of`, `any_of`, `not`, and `leaf`, and the following comparison operators: `eq`, `neq`, `in`, `not_in`, `gt`, `lt`. Missing observation fields are treated as `None` instead of causing exceptions.

Although T3 and T4 are tested in one script (`t3_t4.py`), they produce two independent verdicts. Accordingly, the invariant engine evaluates `verdict_rule_t3` and `verdict_rule_t4` separately.

### Design Note on T6

The paper describes T6 in relation to:

- Q6: Stale IdP Binding.
- Q9: Incomplete Unbinding.
- Q10: Hidden Binding Relationships.

In the current implementation, Q6 is the main decision condition: if both OAuth identities can still access the same account after an identifier change, the old binding was not invalidated.

Q9 describes a related failure mode in which local records are removed but IdP-side tokens remain valid. Since a Q6 violation necessarily implies that the old binding still exists, Q6 detection already subsumes Q9 at the observation level.

Q10 (whether the binding relationship is visible to the user) is a UI-level property that compounds T6 in the paper's taxonomy. In this artifact, the T6 verdict is based on Q6; Q10 is not implemented as a standalone invariant or verdict condition. Q8 is handled separately by T5, which checks whether IdP binding or unbinding operations require user reauthentication.

## 6. Example Runs

`example_runs/` contains sanitized outputs from real-world cases discussed in the paper: the Pinterest motivation case (Section 4.1) and the Case A study (Section 6.7).

### Pinterest T6: The Shadow Binding Attack (Motivation Case, Section 4.1)

This run demonstrates the T6 audit against Pinterest, the motivation case detailed in Section 4.1 (Figure 3). After the primary email was changed, the original Google OAuth binding remained valid. Both the old and the new OAuth identities could access the same account, indicating identity-state desynchronization (Q6).

Files:

- `case_studies/pinterest_t6/report.txt`
- `case_studies/pinterest_t6/state_auditor_result.json`

### T2 Case Study: Verification Context Confusion (Section 6.7, Case A)

This run corresponds to Case A in Section 6.7 (the 2Captcha verification-context-confusion case). A first-party registration for the victim's email left the account in a pending verification state; when the victim later attempted a legitimate sign-up via an IdP, the platform failed to bind the resulting verification signal to the originating session and instead propagated the victim's successful verification to the attacker's pending registration, activating an account under the attacker's control (Q2/Q3).

Files:

- `case_studies/2captcha_t2/report.txt`
- `case_studies/2captcha_t2/state_auditor_result.json`

All test-account credentials have been sanitized.

## 7. Code Navigation

### Three key file types per attack vector

Each vector Tk corresponds to three key artifacts:

- Audit procedure definition - the task composition in `configs/task_compositions.yaml` (referencing intents in `configs/intent_library.yaml`).
- Invariant definition - `configs/invariants.yaml`.
- Task entry point - one of `semantic_navigator/tasks/t1_step1.py`, `t1_step2.py`, `t2.py`, `t3_t4.py`, `t5.py`, `t6.py`, or `t7.py`.

### State Auditor signal flow

`verdict_parser.py::parse_output()` extracts `<observations>`, `<verdict>`, and `<evidence>`. If structured output is missing, it falls back through the three-level parser chain.

### Cross-check logic

`auditor.py::cross_check()` compares the rule verdict and LLM verdict, producing `verified`, `uncertain`, `rule_only`, `llm_only`, `llm_only_na`, or `unavailable`.

### Iterative execution strategy

`iterative_executor.py` implements the multi-round execution logic described in Section 6.2. It supports multi-round aggregation for standard tasks, paired step1 + step2 execution for T1, and dual-verdict aggregation for T3_T4.

## 8. Repository Layout

```text
savior/
  browser_interactor/              # Browser Interactor (Section 5.2.1)
    claude_runner.py               #   LLM invocation + retry/timeout
    url_prefilter.py               #   URL pre-filtering and deduplication
    captcha_solver.py              #   CAPTCHA handler invocation helper
  semantic_navigator/              # Semantic Navigator (Section 5.2.2)
    task_orchestrator.py           #   Prompt assembly + invariant injection
    iterative_executor.py          #   Iterative execution strategy (Section 6.2)
    tasks/                         #   Task entry points wiring all three layers
      t1_step1.py
      t1_step2.py
      t2.py
      t3_t4.py
      t5.py
      t6.py
      t7.py
  state_auditor/                   # State Auditor (Section 5.2.3)
    invariants.py                  #   YAML rule engine
    verdict_parser.py              #   Structured output parsing + fallback
    auditor.py                     #   Preconditions / cross-check / evidence
    evidence_compiler.py           #   Report generation
    screenshot_verifier.py         #   Optional advisory screenshot helper
  runner/                          # Batch experiment executor (Section 6)
    batch_runner.py
  utils/
    credentials.py                 #   Credential collection (via getpass)
    file_utils.py                  #   Directory management
  configs/
    invariants.yaml                #   Q-linked invariant rules
    intent_library.yaml            #   19 reusable intents (directive / interaction)
    task_compositions.yaml         #   Per-vector intent sequences (T1-T7)
  example_runs/
    case_studies/
      pinterest_t6/                # Pinterest motivation-case example (Section 4.1)
      2captcha_t2/                 # T2 example (Section 6.7, Case A)
  main_launcher.py                 # Single-task interactive entry
  oauth_test_runner.py             # Entry point delegating to runner/batch_runner.py
  handler.py                       # CAPTCHA resolution handler
```

## Security and Ethics

This tool is intended solely for responsible-disclosure research under controlled conditions, following the Menlo Report principles described in the paper's Ethical Considerations. All testing uses researcher-controlled accounts; the artifact ships no target-website credentials and no pre-configured attack scripts. Credentials are collected interactively via `getpass` and redacted in output reports.

CAPTCHA challenges are treated as an orthogonal anti-automation mechanism that falls outside the scope of the vulnerability analysis. The artifact provides only a pluggable handler interface with a human-in-the-loop default and does not bundle any automated CAPTCHA-solving implementation. For DoS-related testing (T7), request duration and frequency are kept to the minimum needed to confirm the vulnerability state.

For usage boundaries and ethical assumptions, refer to the paper's Ethical Considerations section.
