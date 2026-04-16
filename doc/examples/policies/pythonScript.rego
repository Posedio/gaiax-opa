package verify.pythonScript

# Example policy that delegates credential-subject validation to an external CLI
# via the cliExec built-in provided by the cli_exec plugin.
#
# Required OPA config (build tag: cli_exec):
#
#   plugins:
#     cli_exec:
#       commands:
#         validate_vat: ["python3", "/opt/scripts/validate_vat.py"]
#
# The second argument is an array; each element is JSON-encoded and appended as a
# positional CLI argument after the base command. The command must print a JSON
# object to stdout.

default allow := false

allow if {
    count(errors) == 0
}

# ------------------------------------------------------------------
# Run the CLI validator for every VatID credential in the input.
# The command receives the full credentialSubject as its first argument
# and the expected country code as the second.
# ------------------------------------------------------------------

vat_results[id] := res if {
    some vc in input.vcs
    "gx:VatID" in vc.type
    id := vc.id
    res := cliExec("validate_vat", [vc.credentialSubject, input.expected_country])
}

# Propagate CLI-level errors (plugin not started, unknown command, etc.)
errors contains msg if {
    some id, res in vat_results
    res.error
    msg := sprintf("cli error for vc %q: %s", [id, res.error])
}

# Reject when the validator marks the VAT ID as invalid
errors contains msg if {
    some id, res in vat_results
    not res.error
    not res.valid
    msg := sprintf("invalid VAT ID in vc %q: %s", [id, res.reason])
}

# Require at least one VatID credential to be present
errors contains msg if {
    count(vat_results) == 0
    msg := "no gx:VatID credential found in input"
}
