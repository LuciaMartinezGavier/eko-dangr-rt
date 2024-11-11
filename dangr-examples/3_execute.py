import random
import logging
import time
from dangr_rt import dangr_analysis, jasm_findings, expression, variables

# angr logger is very verbose
angr_logger = logging.getLogger("angr")
angr_logger.setLevel(logging.ERROR)

logger = logging.getLogger("constraints")
logger.setLevel(logging.INFO)

ENDBR64_INSN = 0xFA1E0FF3

def analyze_match(
    j_match: jasm_findings.JasmMatch,
    dangr: dangr_analysis.DangrAnalysis) -> bool:
    cmp_address = j_match.addrmatch_from_name("cmp-address").value

    logger.info("Initializing match analysis, building DDG...")
    dangr.set_finding(j_match)

    logger.info("Creating variables")
    vf = dangr.get_variable_factory()
    ptr = vf.create_from_capture(j_match.varmatch_from_name('ptr'))
    y = vf.create_from_capture(j_match.varmatch_from_name('y'))
    z = vf.create_from_capture(j_match.varmatch_from_name('z'))
    dx = variables.Deref(ptr)
    dangr.add_variables([dx, y, z, ptr])

    logger.info("Resolving dependencies")
    if not (dangr.depends(ptr, y) or dangr.depends(ptr, z)):
        logger.info("Did not satisfied the dependencies constraints")
        return False

    logger.info("Adding constraints")
    dangr.add_constraint(expression.Eq(y, z))
    dangr.add_constraint(expression.Not(expression.Eq(dx, ENDBR64_INSN)))

    try:
        logger.info("Concretizing arguments...")
        concrete_values = dangr.concretize_fn_args()
        logger.info("Concretized args! %s", concrete_values)
    except TypeError:
        concrete_values = None
        logger.warning("Unsupported arguments, we are still working on "
                    "supporting something else than register arguments")

    logger.info("Symbolic executing function...")
    found_states = dangr.simulate(cmp_address, concrete_values)
    if not found_states:
        logger.info("Could't find a path to the target %s", hex(cmp_address))
        return False

    return not dangr.satisfiable(found_states)

def analyze_random_match():
    jasm_matches = jasm_findings.structural_filter('', 'software_breakpoint_pattern')
    random_idx = random.randint(0, len(jasm_matches) - 1)

    start = time.time()
    logger.info("Let's analyze match number %s", random_idx)

    j_match = jasm_matches[random_idx]

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
    logger.info("CFG finished")

    if analyze_match(j_match, dangr):
        logger.info("Found a match in %s seconds", time.time() - start)
    else:
        logger.info("Not a match, solved in %s seconds", time.time() - start)


analyze_random_match()
