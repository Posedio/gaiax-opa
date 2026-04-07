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
    ex_result
    not ex_result.error
    ex_result.allow
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

base_cs := {"gx:vatID": vat_id, "gx:countryCode": country_code, "schema:name": schema_name} if {
    some vc in vat_id_vcs
    vat_id := vc.credentialSubject["gx:vatID"]
    some code in country_codes
    country_code := code
    some name_vc in schema_name_vcs
    schema_name := name_vc.credentialSubject["schema:name"]
}

suffix := base_cs["schema:name"]

registry_response := http.send({
    "method": "GET",
    "url": concat("", ["https://cache.registry.pontus-x.eu/v1/identities?page=1&limit=20&search=", urlquery.encode(base_cs["schema:name"])]),
    "force_cache": true,
    "force_cache_duration_seconds": 3600,
})

deny contains msg if {
    not registry_response
    msg := "registry lookup could not be performed"
}

deny contains msg if {
    print(registry_response)
    registry_response.status_code != 200
    msg := sprintf("registry lookup failed with status %d", [registry_response.status_code])
}

deny contains msg if {
    registry_response.status_code == 200
    count(registry_response.body.data) == 0
    msg := sprintf("participant '%s' not found in registry", [base_cs["schema:name"]])
}

deny contains msg if {
    registry_response.status_code == 200
    count(registry_response.body.data) > 0
    registry_vat_id := registry_response.body.data[0].credentialsData["gx:VatID"]["gx:vatID"]
    registry_vat_id != base_cs["gx:vatID"]
    msg := sprintf("registry vatID '%s' does not match credential vatID '%s'", [registry_vat_id, base_cs["gx:vatID"]])
}

deny contains msg if {
    registry_response.status_code == 200
    count(registry_response.body.data) > 0
    registry_country_code := registry_response.body.data[0].credentialsData["gx:VatID"]["gx:countryCode"]
    registry_country_code != base_cs["gx:countryCode"]
    msg := sprintf("registry countryCode '%s' does not match credential countryCode '%s'", [registry_country_code, base_cs["gx:countryCode"]])
}

cs := object.union(base_cs, {
    "px:walletAddress": registry_response.body.data[0].walletAddress,
    "px:presentationUrl": registry_response.body.data[0].presentationUrl,
}) if {
    registry_response.status_code == 200
    count(registry_response.body.data) > 0
}

context := {"np": "http://newparticipant.test/ns#", "px": "http://pontus-x.eu/ns#",}

type := "np:Participant"


