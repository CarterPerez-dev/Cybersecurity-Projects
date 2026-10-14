// ©AngelaMos | 2026
// tls.go

package experiment

import "github.com/CarterPerez-dev/khaos/internal/pki"

// FamilyTLS is the family name every certificate experiment carries.
const FamilyTLS = "tls"

// One experiment per certificate trap. The summaries say what the fault CATCHES,
// because several produce byte-identical client errors: self-signed, untrusted-CA
// and missing-intermediate all give `x509: certificate signed by unknown
// authority`.
const (
	NameLeafExpired         = "tls.leaf_expired"
	NameLeafNotYetValid     = "tls.leaf_not_yet_valid"
	NameIntermediateExpired = "tls.intermediate_expired"

	NameWrongSAN       = "tls.wrong_san"
	NameCommonNameOnly = "tls.common_name_only"
	NameNoIPSAN        = "tls.no_ip_san"

	NameSelfSigned          = "tls.self_signed"
	NameUntrustedCA         = "tls.untrusted_ca"
	NameMissingIntermediate = "tls.missing_intermediate"
	NameIssuerNotCA         = "tls.issuer_not_ca"
	NameNameConstraint      = "tls.name_constraint_violation"
	NamePathLength          = "tls.path_length_exceeded"

	NameSHA1Signature  = "tls.sha1_signature"
	NameEKUClientOnly  = "tls.eku_client_auth_only"
	NameEKUConstrained = "tls.eku_constrained_intermediate"

	NameWeakKey           = "tls.weak_key"
	NameExcessiveLifetime = "tls.excessive_lifetime"
	NameNoDigitalSig      = "tls.key_usage_no_digital_signature"

	NameRevokedViaCRL  = "tls.revoked_via_crl"
	NameStaleCRL       = "tls.stale_crl"
	NameCRLUnreachable = "tls.crl_unreachable"

	NameOCSPRevoked     = "tls.ocsp_revoked"
	NameOCSPUnknown     = "tls.ocsp_unknown"
	NameOCSPTryLater    = "tls.ocsp_try_later"
	NameOCSPUnreachable = "tls.ocsp_unreachable"
	NameOCSPStale       = "tls.ocsp_stale"
	NameOCSPWrongSerial = "tls.ocsp_wrong_serial"
	NameOCSPWrongSigner = "tls.ocsp_wrong_signer"
	NameNoOCSPServer    = "tls.no_ocsp_server"

	NameStapleGarbage = "tls.staple_garbage"
	NameStapleAbsent  = "tls.staple_absent"

	NameCASwap = "tls.ca_swap"

	NameClientCertExpired = "tls.mtls_client_expired"
	NameClientCertAbsent  = "tls.mtls_client_absent"

	// Shares the revoked-via-crl TRAP; what differs is the finding, whether a
	// session established before the revocation outlives it.
	NameResumptionAfterRevocation = "tls.resumption_after_revocation"
)

const (
	sumLeafExpired     = "serve an expired certificate, which finds a client that ignores expiry, a proxy serving a stale certificate from cache, and an application that catches the error and retries over plain HTTP"
	sumLeafNotYetValid = "serve a certificate that is not valid yet, which finds a clock-skew tolerance set wide enough to accept anything"
	sumInterExpired    = "serve a valid leaf under an expired intermediate, which finds monitoring that watches leaf expiry only"

	sumWrongSAN       = "serve a certificate for a different host, which finds a client that kept its chain check and dropped its hostname check"
	sumCommonNameOnly = "serve a certificate naming the host only in the legacy CommonName, which finds a client that reimplemented hostname matching or re-enabled the fallback Go removed"
	sumNoIPSAN        = "serve a certificate with no IP SANs to a client dialling by address, which finds a service reached by pod IP with verification disabled because it is internal"

	sumSelfSigned  = "serve a self-signed leaf, which finds InsecureSkipVerify and a trust store carrying a development CA in production"
	sumUntrustedCA = "serve a leaf signed by a CA the target does not trust, which is the shape a man-in-the-middle presents"
	sumMissingInt  = "serve a valid leaf and withhold its intermediate, which finds a deploy that works in a browser chasing AIA and fails in Go"
	sumIssuerNotCA = "serve a leaf signed by a certificate whose basic constraints say it is not a CA, which finds a verifier that does not check them"
	sumConstraint  = "serve a leaf for a name its issuing CA is constrained against, which finds a constrained corporate sub-CA allowed to issue for anything"
	sumPathLength  = "serve a chain deeper than its CA's path length permits, which finds a custom verifier ignoring pathLenConstraint"

	sumSHA1           = "serve a leaf signed with SHA-1 RSA, which finds GODEBUG=x509sha1=1 left set or a vendored fork with the check removed"
	sumEKUClientOnly  = "serve a leaf that permits client authentication only, which finds a deploy that swapped the server and client secrets"
	sumEKUConstrained = "serve a blameless leaf under a CA authorised for client authentication only, which finds a sub-CA whose scope nobody enforces"

	sumWeakKey      = "serve a leaf with an undersized RSA key, which crypto/x509 accepts without complaint because path validation has no minimum at all; this measures whether the target has a floor of its own"
	sumLifetime     = "serve a leaf valid for far longer than any policy allows, which nothing outside a browser enforces"
	sumNoDigitalSig = "serve a leaf whose KeyUsage omits digitalSignature, making it unusable for TLS under RFC 5280, which Verify never checks because it enforces EXTENDED key usage and not these bits"

	sumRevokedCRL      = "revoke the certificate in a valid, in-date CRL from its own issuer, which crypto/x509 accepts because it performs no revocation checking of any kind and has no option to turn it on; khaos reports UNSUPPORTED rather than a pass when the target never asked"
	sumStaleCRL        = "serve a CRL whose freshness window has closed and which predates the revocation, which finds a client that fetches and parses a list and never checks whether it is current"
	sumCRLUnreachable  = "refuse the CRL endpoint while every other endpoint stays up, which finds a client that reads could-not-fetch as not-revoked"
	sumOCSPRevoked     = "answer revocation queries with a signed Revoked response, which a correct client must refuse outright"
	sumOCSPUnknown     = "answer with a signed Unknown response, which finds a client that collapses do-not-know into good"
	sumOCSPTryLater    = "answer with TryLater, the soft-fail trap: the responder is reachable and answering and declining to say, which is the exact shape that makes revocation near-useless in practice"
	sumOCSPUnreachable = "refuse the OCSP endpoint while every other endpoint stays up, which finds the soft-fail that proceeds on no answer at all"
	sumOCSPStale       = "answer with a correctly signed Good response whose freshness window has closed, which x/crypto/ocsp parses without complaint, so a replayed Good is trusted forever"
	sumOCSPWrongSerial = "answer with a signed Good response minted for a different certificate, which ParseResponseForCert refuses and ParseResponse accepts; that one word is a total bypass of revocation checking"
	sumOCSPWrongSigner = "answer with a response signed by a key the CA never delegated, which is caught only by a client that checks the signature"
	sumNoOCSPServer    = "serve a leaf naming no responder at all, as Let's Encrypt has issued since 2025, and measure whether the target falls back to the CRL or treats nothing-to-ask as fine"

	sumStapleGarbage = "staple bytes that are not an OCSP response, which Go never parses and delivers to the application verbatim"
	sumStapleAbsent  = "omit the stapled response entirely, which finds an application that reads no staple as good instead of asking the responder itself"

	sumCASwap = "replace the root the target trusts with one khaos controls and serve a chain that is valid under it, which NOTHING in a TLS client can detect; the only defences are pinning and certificate transparency, and this experiment exists to show that acceptance here is not a bug in the client"

	sumClientExpired = "require mutual TLS and issue the target an expired client identity, which khaos's server then refuses; under TLS 1.3 the target's tls.Dial SUCCEEDS anyway and the refusal only surfaces on the first read, so this finds a client that treats a completed dial as a working connection"
	sumClientAbsent  = "require mutual TLS and issue the target no client identity at all, which is what a failed rotation and a bypassed sidecar look like; an attacker does not present a bad certificate, they present nothing"

	sumResumption = "establish a session while the certificate is good and revoke it afterwards, which a resumed connection never notices: crypto/tls does not run VerifyPeerCertificate on a resumed handshake, so an application whose pinning or revocation check lives in that hook enforces it once and skips it for the ticket's lifetime, which Go caps at seven days"
)

// caSwapPolarity is the one experiment whose acceptance is not a finding: once
// the anchor is replaced the chain is genuinely valid and no client can see it.
var caSwapPolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a replaced trust anchor makes the chain genuinely valid and no client-side check can detect it, so accepting it is correct behaviour rather than a defect; only dropping enforcement would be one",
}

func init() {
	groups := [][]Definition{
		subjectExperiments(),
		chainExperiments(),
		policyExperiments(),
		revocationExperiments(),
		mutualExperiments(),
	}

	for _, group := range groups {
		for _, definition := range group {
			catalog[definition.Name] = definition
		}
	}
}

// subjectExperiments are the faults in WHEN a certificate is valid and WHO for.
func subjectExperiments() []Definition {
	return []Definition{
		// Validity.
		tlsDefinition(tlsSpec{
			name:    NameLeafExpired,
			summary: sumLeafExpired,
			trap:    pki.LeafExpired,
			extra:   []Param{certWindowParam},
		}),
		tlsDefinition(tlsSpec{
			name:    NameLeafNotYetValid,
			summary: sumLeafNotYetValid,
			trap:    pki.LeafNotYetValid,
			extra:   []Param{certWindowParam},
		}),
		tlsDefinition(tlsSpec{
			name:    NameIntermediateExpired,
			summary: sumInterExpired,
			trap:    pki.IntermediateExpired,
			extra:   []Param{certWindowParam},
		}),

		// Identity.
		tlsDefinition(tlsSpec{
			name:    NameWrongSAN,
			summary: sumWrongSAN,
			trap:    pki.WrongSAN,
		}),
		tlsDefinition(tlsSpec{
			name:    NameCommonNameOnly,
			summary: sumCommonNameOnly,
			trap:    pki.CommonNameOnly,
		}),
		tlsDefinition(tlsSpec{
			name:    NameNoIPSAN,
			summary: sumNoIPSAN,
			trap:    pki.NoIPSAN,
		}),
	}
}

// chainExperiments are the faults in the path from leaf to trusted root, plus
// the two in how it is signed and what it may be used for.
func chainExperiments() []Definition {
	return []Definition{
		// The chain.
		tlsDefinition(tlsSpec{
			name:    NameSelfSigned,
			summary: sumSelfSigned,
			trap:    pki.SelfSigned,
		}),
		tlsDefinition(tlsSpec{
			name:    NameUntrustedCA,
			summary: sumUntrustedCA,
			trap:    pki.UntrustedCA,
		}),
		tlsDefinition(tlsSpec{
			name:    NameMissingIntermediate,
			summary: sumMissingInt,
			trap:    pki.MissingIntermediate,
		}),
		tlsDefinition(tlsSpec{
			name:    NameIssuerNotCA,
			summary: sumIssuerNotCA,
			trap:    pki.IssuerNotCA,
		}),
		tlsDefinition(tlsSpec{
			name:    NameNameConstraint,
			summary: sumConstraint,
			trap:    pki.NameConstraintViolation,
		}),
		tlsDefinition(tlsSpec{
			name:    NamePathLength,
			summary: sumPathLength,
			trap:    pki.PathLengthExceeded,
		}),

		// Signing and usage.
		tlsDefinition(tlsSpec{
			name:    NameSHA1Signature,
			summary: sumSHA1,
			trap:    pki.SHA1Signature,
		}),
		tlsDefinition(tlsSpec{
			name:    NameEKUClientOnly,
			summary: sumEKUClientOnly,
			trap:    pki.EKUClientAuthOnly,
		}),
		tlsDefinition(tlsSpec{
			name:    NameEKUConstrained,
			summary: sumEKUConstrained,
			trap:    pki.EKUConstrainedIntermediate,
		}),
	}
}

// policyExperiments are the faults crypto/x509 ACCEPTS, so none of them tests
// the library: they test whether the target imposed a policy of its own.
func policyExperiments() []Definition {
	return []Definition{
		tlsDefinition(tlsSpec{
			name:    NameWeakKey,
			summary: sumWeakKey,
			trap:    pki.WeakKey,
			extra:   []Param{certBitsParam},
		}),
		tlsDefinition(tlsSpec{
			name:    NameExcessiveLifetime,
			summary: sumLifetime,
			trap:    pki.ExcessiveLifetime,
			extra:   []Param{certDaysParam},
		}),
		tlsDefinition(tlsSpec{
			name:    NameNoDigitalSig,
			summary: sumNoDigitalSig,
			trap:    pki.KeyUsageWithoutDigitalSignature,
		}),

		// The trust store, which sits here because the chain is impeccable under
		// an anchor khaos replaced.
		tlsDefinition(tlsSpec{
			name:     NameCASwap,
			summary:  sumCASwap,
			trap:     pki.CASwap,
			polarity: caSwapPolarity,
		}),
	}
}

// revocationExperiments are the faults in what an authority SAYS about a
// certificate, each declaring the endpoint that turns on the UNSUPPORTED reading.
func revocationExperiments() []Definition {
	return []Definition{
		// By CRL.
		tlsDefinition(tlsSpec{
			name:     NameRevokedViaCRL,
			summary:  sumRevokedCRL,
			trap:     pki.RevokedViaCRL,
			consults: ConsultsCRL,
		}),
		tlsDefinition(tlsSpec{
			name:     NameStaleCRL,
			summary:  sumStaleCRL,
			trap:     pki.StaleCRL,
			consults: ConsultsCRL,
			extra:    []Param{certWindowParam},
		}),
		tlsDefinition(tlsSpec{
			name:     NameCRLUnreachable,
			summary:  sumCRLUnreachable,
			trap:     pki.CRLUnreachable,
			consults: ConsultsCRL,
		}),

		// By OCSP.
		tlsDefinition(tlsSpec{
			name:     NameOCSPRevoked,
			summary:  sumOCSPRevoked,
			trap:     pki.OCSPRevoked,
			consults: ConsultsOCSP,
		}),
		tlsDefinition(tlsSpec{
			name:     NameOCSPUnknown,
			summary:  sumOCSPUnknown,
			trap:     pki.OCSPUnknown,
			consults: ConsultsOCSP,
		}),
		tlsDefinition(tlsSpec{
			name:     NameOCSPTryLater,
			summary:  sumOCSPTryLater,
			trap:     pki.OCSPTryLater,
			consults: ConsultsOCSP,
		}),
		tlsDefinition(tlsSpec{
			name:     NameOCSPUnreachable,
			summary:  sumOCSPUnreachable,
			trap:     pki.OCSPUnreachable,
			consults: ConsultsOCSP,
		}),
		tlsDefinition(tlsSpec{
			name:     NameOCSPStale,
			summary:  sumOCSPStale,
			trap:     pki.OCSPStale,
			consults: ConsultsOCSP,
			extra:    []Param{certWindowParam},
		}),
		tlsDefinition(tlsSpec{
			name:     NameOCSPWrongSerial,
			summary:  sumOCSPWrongSerial,
			trap:     pki.OCSPWrongSerial,
			consults: ConsultsOCSP,
		}),
		tlsDefinition(tlsSpec{
			name:     NameOCSPWrongSigner,
			summary:  sumOCSPWrongSigner,
			trap:     pki.OCSPWrongSigner,
			consults: ConsultsOCSP,
		}),
		tlsDefinition(tlsSpec{
			name:     NameNoOCSPServer,
			summary:  sumNoOCSPServer,
			trap:     pki.NoOCSPServer,
			consults: ConsultsCRL,
		}),

		// Stapling.
		tlsDefinition(tlsSpec{
			name:     NameStapleGarbage,
			summary:  sumStapleGarbage,
			trap:     pki.StapleGarbage,
			consults: ConsultsOCSP,
		}),
		tlsDefinition(tlsSpec{
			name:     NameStapleAbsent,
			summary:  sumStapleAbsent,
			trap:     pki.StapleAbsent,
			consults: ConsultsOCSP,
		}),
	}
}

// mutualExperiments test whether the target NOTICES being refused, which under
// TLS 1.3 comes down to whether it reads: the dial succeeds either way.
func mutualExperiments() []Definition {
	return []Definition{
		tlsDefinition(tlsSpec{
			name:    NameClientCertExpired,
			summary: sumClientExpired,
			trap:    pki.ClientCertExpired,
			extra:   []Param{certWindowParam},
		}),
		tlsDefinition(tlsSpec{
			name:    NameClientCertAbsent,
			summary: sumClientAbsent,
			trap:    pki.ClientCertAbsent,
		}),

		// The same trap as tls.revoked_via_crl, deliberately: a target can check
		// revocation and still never notice it on a resumed session.
		tlsDefinition(tlsSpec{
			name:     NameResumptionAfterRevocation,
			summary:  sumResumption,
			trap:     pki.RevokedViaCRL,
			consults: ConsultsCRL,
		}),
	}
}
