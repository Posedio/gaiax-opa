package compliance.legalPerson

default allow := false

result := {
    "allow": allow,
    "errors": deny,
    "suffix": suffix,
}

ex_result:= externalPDP("legalPerson", {"input":input})

deny contains msg if {
    not ex_result
    msg := "external PDP unavailable"
}

deny contains msg if {
    ex_result.error
    msg := ex_result.error
}

allow if {
    not ex_result.error
    ex_result.allow
}

allow if {
    ex_result
    not ex_result.error
    count(deny) == 0
}

re := resolveVPFromJWTWithGXCompliance(input.jwt)

deny contains msg if {
    not re
    msg := "internal error"
}


deny contains msg if {
    re.error
    msg := re.error
}

vat_id_vcs contains vc if {
    some vc in re.vcs
    vc.credentialSubject["gx:vatID"]
}

deny contains msg if {
    count(vat_id_vcs) == 0
    msg := "no VC with gx:vatID found"
}

country_code_vcs contains vc if {
    some vc in re.vcs
    vc.credentialSubject["gx:countryCode"]
}

deny contains msg if {
    count(country_code_vcs) == 0
    msg := "no VC with gx:countryCode found"
}

deny contains msg if {
    count(country_code_vcs) != 2
    msg := "expected exactly two VCs with gx:countryCode"
}

country_codes := {code | some vc in country_code_vcs; code := vc.credentialSubject["gx:countryCode"]}

deny contains msg if {
    count(country_codes) != 1
    msg := "gx:countryCode values across VCs do not match"
}

schema_name_vcs contains vc if {
    some vc in re.vcs
    vc.credentialSubject["schema:name"]
}

deny contains msg if {
    count(schema_name_vcs) == 0
    msg := "no VC with schema:name found"
}

cs := {"gx:vatID": vat_id, "gx:countryCode": country_code, "schema:name": schema_name} if {
    some vc in vat_id_vcs
    vat_id := vc.credentialSubject["gx:vatID"]
    some code in country_codes
    country_code := code
    some name_vc in schema_name_vcs
    schema_name := name_vc.credentialSubject["schema:name"]
}

suffix := cs["schema:name"]

context := {"np": "http://newparticipant.test/ns#"}

type := "np:Participant"


