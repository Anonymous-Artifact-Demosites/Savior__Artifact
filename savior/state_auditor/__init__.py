"""State Auditor layer for SAVIOR."""

from .auditor import capture_evidence, cross_check, cross_check_with_evidence, extract_vulnerable_path
from .evidence_compiler import (
    compile_t1s1_report,
    compile_t1s1_result,
    compile_t1s2_result,
    compile_t2_report,
    compile_t2_result,
    compile_t3_report,
    compile_t3t4_result,
    compile_t4_report,
    compile_t5_report,
    compile_t5_result,
    compile_t6_report,
    compile_t6_result,
    compile_t7_report,
    compile_t7_result,
    write_report_file,
    write_result_file,
)
from .invariants import evaluate_invariants, get_task_config
from .screenshot_verifier import verify_observations
from .verdict_parser import parse_output
