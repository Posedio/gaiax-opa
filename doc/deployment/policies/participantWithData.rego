package verify.legalPersonData

default allow := false


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
        not issuer in data.valid_issuer #see data.json
    msg := "Only valid_issuer are allowed"
}


odrlRes := res if {
 odrl_request := {
         "principal": "https://example.com/per:5234",
         "target": "http://example.com/document:1234",
         "action": "use",
         "requestContext": {
             "version": "1.0.0",
             "vcs": re.vcs
         }

 }
 res := odrl(data.odrl_policy_1, odrl_request) #see data
}


deny contains msg if{
    odrlRes.error
    msg := odrlRes.error
}


deny contains msg if {
    not odrlRes
    msg := "internal error on odrl eval"
}


deny contains msg if{
    not odrlRes.ok
    msg := odrlRes.report
}
