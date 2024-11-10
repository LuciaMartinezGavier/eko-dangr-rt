import random
import logging
import time
from dangr_rt import dangr_analysis, jasm_findings, expression, variables

# angr logger is very verbose
angr_logger = logging.getLogger("angr")
angr_logger.setLevel(logging.ERROR)

logger = logging.getLogger("constraints")
logger.setLevel(logging.INFO)

def analyze_match(
    j_match: jasm_findings.JasmMatch,
    dangr: dangr_analysis.DangrAnalysis) -> bool:
    cmp_address = j_match.addrmatch_from_name("cmp-address").value

    dangr.set_finding(j_match)

    vf = dangr.get_variable_factory()
    ptr = vf.create_from_capture(j_match.varmatch_from_name('ptr'))
    y = vf.create_from_capture(j_match.varmatch_from_name('y'))
    z = vf.create_from_capture(j_match.varmatch_from_name('z'))
    dx = variables.Deref(ptr)
    dangr.add_variables([dx, y, z, ptr])

    if not (dangr.depends(ptr, y) or dangr.depends(ptr, z)):
        return False

    dangr.add_constraint(expression.Eq(y, z))
    dangr.add_constraint(expression.Not(expression.Eq(dx, 0xFA1E0FF3)))

    try:
        concrete_values = dangr.concretize_fn_args()
    except TypeError:
        concrete_values = None

    found_states = dangr.simulate(cmp_address, concrete_values)
    if not found_states:
        return False

    if not dangr.satisfiable(found_states):
        return True

def analyze_random_match():
    start = time.time()
    jasm_matches = jasm_findings.structural_filter('', 'software_breakpoint_pattern')

    logger.info("Initializing analysis (building CFG...)")
    dangr = dangr_analysis.DangrAnalysis(
        binary_path='liblzma.so.5.6.1',
        config={
            'cfg_max_steps': 20,
            'cfg_resolve_indirect_jumps': False,
            'max_depth': 1,
            'timeout': 2
        }
    )
    logger.info("CFG finished in %s seconds", round(time.time() - start, 2))
    for i, j_match in enumerate(jasm_matches):
        logger.info("Starting analysis in match %s", i)
        if analyze_match(j_match, dangr):
            logger.info("Found a match in %s seconds", round(time.time() - start, 4))
            return

    logger.info("Didn't found any match, solved in %s seconds", round(time.time() - start, 4))

analyze_random_match()
