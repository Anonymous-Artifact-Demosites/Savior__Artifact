"""Task orchestration for the Semantic Navigator layer (Section 5.2.2).

Implements CONSTRUCTPROMPT from Algorithm 1: loads the prompt template,
injects auditor context from invariants, and substitutes variables.
"""

from pathlib import Path
from string import Template

import yaml

from savior.browser_interactor.claude_runner import run_claude


USE_COMPOSITION_MODE = True


def _prompt_path(task_id):
    """Map a task identifier to its prompt template path."""
    normalized = task_id.upper()
    mapping = {
        "T1_STEP1": "t1_step1.txt",
        "T1_STEP2": "t1_step2.txt",
        "T2": "t2.txt",
        "T3_T4": "t3_t4.txt",
        "T5": "t5.txt",
        "T6": "t6.txt",
        "T7": "t7.txt",
    }
    filename = mapping.get(normalized)
    if filename is None:
        raise KeyError(f"No prompt template configured for {task_id}")
    return Path(__file__).resolve().parent / "prompts" / filename


def _config_path(filename):
    """Return a config path, supporting bundled and repository-root layouts."""
    base = Path(__file__).resolve()
    bundled = base.parents[1] / "configs" / filename
    if bundled.exists():
        return bundled
    return base.parents[2] / "configs" / filename


def _load_yaml_config(filename):
    with open(_config_path(filename), "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _intent_fragments():
    library = _load_yaml_config("intent_library.yaml")
    return {intent["id"]: intent["prompt_fragment"] for intent in library.get("intents", [])}


def _normalize_placeholder_style(text):
    """Convert ${var} placeholders back to the source template's $var style."""
    import re as _re
    return _re.sub(r"\$\{([a-zA-Z_]\w*)\}", r"$\1", text)


def _compose_from_intents(task_id, variables):
    """Assemble a prompt from task composition and intent library configs."""
    compositions = _load_yaml_config("task_compositions.yaml")
    task = compositions["tasks"][task_id.upper()]
    fragments = compositions.get("fragments", {})
    intents = _intent_fragments()

    parts = []
    for entry in task.get("composition", []):
        if "fragment_ref" in entry:
            parts.append(fragments[entry["fragment_ref"]])
            continue

        substitute_vars = False
        if "custom_fragment" in entry:
            fragment = entry["custom_fragment"]
        elif "intent" in entry:
            fragment = intents[entry["intent"]]
            substitute_vars = True
        else:
            continue

        if substitute_vars and entry.get("vars"):
            scoped_vars = dict(variables)
            scoped_vars.update(entry["vars"])
            fragment = Template(fragment).safe_substitute(scoped_vars)

        parts.append(fragment)

    return _normalize_placeholder_style("".join(part for part in parts if part is not None))


def _build_auditor_context(task_id):
    """Build the auditor context preamble from invariant descriptions.

    Corresponds to the context injection step of CONSTRUCTPROMPT (Alg. 1 line 1).
    The preamble tells the LLM which security properties the auditor cares about,
    so it can ensure its observations cover the relevant facts.
    """
    try:
        from savior.state_auditor.invariants import get_task_config
        config = get_task_config(task_id)
    except KeyError:
        return ""

    invariants = config.get("invariants", [])
    if not invariants:
        return ""

    lines = [
        "[Auditor Context -- for your awareness while performing this task]",
        "The following security properties are being verified:",
    ]
    for inv in invariants:
        ref = inv.get("reference", "")
        desc = inv.get("description", "").strip().replace("\n", " ")
        lines.append(f"- {inv['id']} ({ref}): {desc}")
    lines.append("Please ensure your observations cover the facts needed to evaluate these properties.")
    return "\n".join(lines)


def construct_prompt(task_id, variables):
    """Load and substitute the prompt for a single task execution.

    Implements CONSTRUCTPROMPT (Alg. 1 line 1): loads the template file,
    injects auditor context from invariants.yaml, and substitutes all
    $variable placeholders via string.Template.safe_substitute().
    """
    if USE_COMPOSITION_MODE:
        try:
            text = _compose_from_intents(task_id, variables)
        except (FileNotFoundError, KeyError):
            text = _load_from_template(task_id, variables)
    else:
        text = _load_from_template(task_id, variables)

    # Inject auditor context if not already provided by caller
    if "auditor_context" not in variables:
        variables = dict(variables)  # don't mutate caller's dict
        variables["auditor_context"] = _build_auditor_context(task_id)

    prompt = Template(text).safe_substitute(variables)

    # Warn about unresolved $placeholders (safe_substitute leaves them intact)
    import re as _re
    unresolved = _re.findall(r"\$([a-zA-Z_]\w*)", prompt)
    # Filter out variables that were actually provided
    unresolved = [f"${name}" for name in unresolved if name not in variables]
    if unresolved:
        import warnings
        warnings.warn(f"Unresolved prompt placeholders: {', '.join(sorted(set(unresolved))[:5])}")

    return prompt


def _load_from_template(task_id, variables):
    """Load the raw prompt template for a task."""
    prompt_path = _prompt_path(task_id)
    return prompt_path.read_text(encoding="utf-8")


def execute_task(task_id, variables, timeout_seconds=600, max_retries=2):
    """Construct a prompt, run Claude, and return both prompt and raw output."""
    prompt = construct_prompt(task_id, variables)
    result = run_claude(prompt, timeout_seconds=timeout_seconds, max_retries=max_retries)
    result["prompt"] = prompt
    return result
