package verify.verifiablePresentation

default allow = false


allow if {
    vcs := resolveVPFromJWT(input.jwt)
    vcs[_].issuer == "did:web:did.dumss.me"
    "gx:ServiceOffering" == vcs[i].type[j]
    print(vcs[i])
}