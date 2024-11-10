"""

############################ STRUCTURAL FILTER ############################

To run Jasm all you need to do is call `jasm_findings.structural_filter`

NOTE:
Right now this is mocked and not really working. 
 - the binary_path argument is ignored
 - software_breakpoint_pattern is the only valid pattern and returns the
   structural findings that jasm *will* return once it is fully implemented :)

This is the kind of patterns that we want to support with jasm

pattern:
- add:
    - $deref:
    main_reg: "@any-ptr" # we can define names for the capture groups
    - "@any"
- cmp:
    - "@any-y"
    - "@any-z"
    address-capture: cmp-address # also, we can define addresses to access later

Sorry for the inconvienience!
"""

from dangr_rt import jasm_findings
jasm_matches = jasm_findings.structural_filter('ignored', 'software_breakpoint_pattern')

print(f"We have {len(jasm_matches)} matches!")

first_match = jasm_matches[0]

print("You can access the 'cmp-address' capture for any match:",
      first_match.addrmatch_from_name('cmp-address'))

print("This pattern also defined the variables ptr, y and z, accesible from any match:")
print("\tptr variable match: ", first_match.varmatch_from_name('ptr'))
