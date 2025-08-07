package verify.legalPerson

default allow = false

# TODO: move to data
valid_issuer := {"did:web:gx-notary.arsys.es:v2",  "did:web:did.dumss.me", "did:web:www.delta-dao.com:notary:v2", "did:web:compliance.lab.gaia-x.eu:main"}

result := {
    "allow": allow,
    "errors": deny
}

allow if {
    count(deny) == 0
}

re := resolveVPFromJWT(input.jwt)


deny contains msg if {
    # talk to stefan what his extension does in case of an invalid jwt
    not re.vcs
    msg := "Invalid JWT"
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
                }
            ]
        }
    ]
}


deny contains msg if{
    odrl_request := {
        "principal": "https://example.com/per:5234",
        "target": "http://example.com/document:1234",
        "action": "use",
        "requestContext": {
            "version": "1.0.0",
            "vcs": re.vcs
        }

    }
    not odrl(odrl_policy, odrl_request)

    msg := "failed odrl"
}