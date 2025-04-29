package verify.verifiablePresentation

# TODO: move to data
valid_issuer := {"did:web:gx-notary.arsys.es:v2",  "did:web:did.dumss.me"}

default allow = false

result := {
    "allow": allow,
    "errors": deny
}

allow if {
    count(deny) == 0
}

vcs := resolveVPFromJWT(input.jwt)

deny contains msg if {
    # talk to stefan what his extension does in case of an invalid jwt
    not vcs
    msg := "Invalid JWT"
}

all_issuers_in_vp contains issuer if {
    issuer := vcs[_].issuer
} 

# Only allow valid_issuers
deny contains msg if {
    some issuer in all_issuers_in_vp
        not issuer in valid_issuer
    msg := "Only stefan and compliance are allowed as issuer!"
}

service_offerings contains so if {
    some vc in vcs
    some type in vc.type
    type ==  "gx:ServiceOffering"
    so := vc
}

# At least one service offering
deny contains msg if {    
    count(service_offerings) == 0
    msg := "VP needs to at least contain one service offering"
}
