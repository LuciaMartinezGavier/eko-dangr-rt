import logging
from dangr_rt import jasm_findings
from dangr_rt import dangr_analysis

# angr logger is very verbose
angr_logger = logging.getLogger("angr")
angr_logger.setLevel(logging.ERROR)

logger = logging.getLogger("dependencies")
logger.setLevel(logging.INFO)

def analyze_match(
    j_match: jasm_findings.JasmMatch,
    dangr: dangr_analysis.DangrAnalysis) -> bool:

    dangr.set_finding(j_match)
    vf = dangr.get_variable_factory()
    ptr = vf.create_from_capture(j_match.varmatch_from_name('ptr'))
    y = vf.create_from_capture(j_match.varmatch_from_name('y'))
    z = vf.create_from_capture(j_match.varmatch_from_name('z'))
    dangr.add_variables([y, z])
    return dangr.depends(ptr, y) or dangr.depends(ptr, z)

def analyze_dependencies():
    jasm_matches = jasm_findings.structural_filter('ignored', 'software_breakpoint_pattern')

    # When we instanciate DangrAnlysis, the CFG is calculated.
    # This might take a while but it is calculated once
    logger.info("Creating CFG...")
    dangr = dangr_analysis.DangrAnalysis(
        binary_path='liblzma.so.5.6.1',
        config={'cfg_max_steps': 20, 'cfg_resolve_indirect_jumps': False}
    )

    relevant_matches = []
    for j_match in jasm_matches:
        dependency_found = analyze_match(j_match, dangr)

        if dependency_found:
            logger.info("Match satisfied (ptr -> y) or (ptr -> z)")
            relevant_matches.append(j_match)
        else:
            logger.info("Match did not satisfied the dependencies")

    logger.info("Out of %s matches, %s satisfy the dependency given",
                len(jasm_matches), len(relevant_matches))

analyze_dependencies()
