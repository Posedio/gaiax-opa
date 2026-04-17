package odrl

default allow = false

result := {
    "allow": allow,
}


vp := resolveVPFromJWT(input.jwt)

odrl_request := {
    "principal": input.principal,
    "target": input.target,
    "action": input.action,
    "requestContext": {
        "vcs": vp.vcs
    }
}

allow if {
    input.principal == vp.issuer
}


allow if {
    odrl(input.policy, odrl_request)
}