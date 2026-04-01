package compliance.legalPerson

default allow := false

valid_issuer:= {"did:web:gx-notary.arsys.es:v2",  "did:web:did.dumss.me", "did:web:www.delta-dao.com:notary:v2", "did:web:compliance.lab.gaia-x.eu:main", "did:web:gx-notary.gxdch.dih.telekom.com:v2", "did:web:validate.posedio.com", "did:web:aerospace-digital-exchange.eu:compliance:v2", "did:web:aerospace-digital-exchange.eu:notary:v2", "did:web:did.dumss.me:verena"}


result := {
    "allow": allow,
    "errors": deny
}

allow if {
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

deny contains msg if {
    not re
    not re.vcs
    msg := "no vcs resolved "
}



all_issuers_in_vp contains issuer if {
    issuer := re.vcs[_].issuer
}

# Only allow valid_issuers
deny contains msg if {
    some issuer in all_issuers_in_vp
        not issuer in valid_issuer #see data.json
    msg := "Only valid_issuer are allowed"
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
