package verify.legalPerson

default allow := false

# TODO: move to data
valid_issuer := {"did:web:gx-notary.arsys.es:v2",  "did:web:did.dumss.me", "did:web:www.delta-dao.com:notary:v2", "did:web:compliance.lab.gaia-x.eu:main", "did:web:gx-notary.gxdch.dih.telekom.com:v2"}

result := {
    "allow": allow,
    "errors": deny
}

allow if {
    count(deny) == 0
}

re := resolveVPFromJWT(input.jwt)

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
        not issuer in valid_issuer
    msg := "Only stefan and compliance are allowed as issuer!"
}




odrl_policy := {
    "@context": "http://www.w3.org/ns/engine.jsonld",
    "@type": "Offer",
    "uid": "http://what.example.com/policy:6163",
    "target": "http://example.com/document:1234",
    "assigner": "http://example.com/org:616",
    "assignee": "https://example.com/per:5234",
    "permission": [
        {
            "action": "use",
            "constraint": [
                {
                    "ovc:leftOperand": "$.credentialSubject.gx:vatID",
                    "operator": "eq",
                    "rightOperand": "ATU75917607",
                    "ovc:credentialSubjectType": "gx:VatID"
                },
                {
                    "ovc:leftOperand": "$.credentialSubject.gx:gaiaxTermsAndConditions",
                    "operator": "eq",
                    "rightOperand": "4bd7554097444c960292b4726c2efa1373485e8a5565d94d41195214c5e0ceb3",
                    "ovc:credentialSubjectType": "gx:Issuer"
                },
                {
                    "ovc:leftOperand": "$.credentialSubject.gx:rulesVersion",
                    "operator": "eq",
                    "rightOperand": "CD25.03",
                    "ovc:credentialSubjectType": "gx:LabelCredential"
                },
                {
                    "ovc:leftOperand": "$.credentialSubject.gx:validatedCriteria[:]",
                    "operator": "eq",
                    "rightOperand": "https://docs.gaia-x.eu/policy-rules-committee/compliance-document/25.03/criteria_participant/#PA1.1",
                    "ovc:credentialSubjectType": "gx:LabelCredential"
                }
            ]
        }
    ]
}

odrl_request := {
        "principal": "https://example.com/per:5234",
        "target": "http://example.com/document:1234",
        "action": "use",
        "requestContext": {
            "version": "1.0.0",
            "vcs": re.vcs
        }

}

odrlRes := odrl(odrl_policy, odrl_request)

deny contains msg if {
    not odrlRes
    msg := "no odrl policy decision"
}


deny contains msg if{
    not odrlRes.ok
    msg := odrlRes.report
}