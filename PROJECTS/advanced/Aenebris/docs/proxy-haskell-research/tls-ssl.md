# TLS/SSL & Let's Encrypt ACME Protocol: Complete Implementation Guide

Transport Layer Security (TLS) implementation remains critical for production systems in 2025, with TLS 1.3 now mandatory for federal systems and industry standards pushing toward stronger security defaults. This guide provides comprehensive technical documentation for implementing secure TLS/SSL infrastructure with focus on Haskell libraries and ACME automation.

## TLS protocol evolution: From 2-RTT to 1-RTT handshakes

**TLS 1.3 achieves 50% faster handshakes** through fundamental protocol redesign. The TLS 1.2 handshake requires two full round-trip times before application data flows, taking 200-400ms on typical networks. TLS 1.3 reduces this to a single round-trip by having clients send speculative key shares in the ClientHello message, enabling servers to derive shared secrets immediately. The simplified protocol removes 20+ years of accumulated vulnerabilities by eliminating CBC mode ciphers, static RSA key exchange, and compression—each responsible for major security incidents.

The handshake differences reveal security improvements. TLS 1.2 transmits the entire handshake in cleartext except the final Finished messages, exposing certificate chains and negotiated parameters to network observers. TLS 1.3 encrypts all handshake messages after ServerHello, protecting certificate information and reducing surveillance capabilities. The protocol mandates forward secrecy through ephemeral key exchange (ECDHE/DHE only), meaning session keys remain secure even if long-term private keys are later compromised—a crucial property TLS 1.2's RSA key exchange lacked.

Cipher suite configuration drastically simplifies in TLS 1.3. Where TLS 1.2 requires specifying key exchange, authentication, encryption, and MAC algorithms separately (like `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`), **TLS 1.3 reduces this to just bulk cipher and hash** (`TLS_AES_128_GCM_SHA256`). Only five cipher suites exist, all using Authenticated Encryption with Associated Data (AEAD). The protocol removes all vulnerable legacy options: RC4, 3DES, CBC mode, MD5, SHA-1 MACs, and anonymous/NULL ciphers all vanish. This eliminates entire attack classes including BEAST, CRIME, Lucky13, and POODLE.

### Modern cipher suite selection for 2025

For production deployments supporting both TLS 1.2 and 1.3, **configure cipher suites in strict order**: `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_256_GCM_SHA384` for TLS 1.3, followed by `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES128-GCM-SHA256`, `ECDHE-ECDSA-CHACHA20-POLY1305`, and `ECDHE-RSA-CHACHA20-POLY1305` for TLS 1.2 compatibility. Every cipher must provide Perfect Forward Secrecy through ephemeral key exchange. Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 completely—they're deprecated since 2020 and vulnerable to protocol downgrade attacks.

The most critical configuration: **enable server cipher order preference**. Without this, malicious clients can force weak cipher selection through downgrade attacks. Set `ssl_prefer_server_ciphers on` in Nginx or `SSLHonorCipherOrder On` in Apache. Prioritize AEAD ciphers (GCM, ChaCha20-Poly1305), prefer ECDHE over DHE for performance, and exclude any cipher suite lacking ephemeral key exchange. Never use ciphers with RSA key exchange (`TLS_RSA_*`), which remain vulnerable to ROBOT attacks and provide no forward secrecy.

For Diffie-Hellman parameters, **use minimum 2048-bit groups**, preferably 3072-bit for enhanced security. TLS 1.3 standardizes predefined FFDHE groups from RFC 7919 (ffdhe2048, ffdhe3072, ffdhe4096) and elliptic curve groups (X25519, X448, P-256, P-384). X25519 provides the best performance-security balance and should be your first choice. Generate custom DH parameters for TLS 1.2: `openssl dhparam -out dhparam.pem 2048`.

### Certificate validation and chain building

Certificate validation requires building a trust chain from the end-entity certificate to a trusted root CA. The process involves cryptographic signature verification of each certificate by its issuer, validity period checking (notBefore ≤ current_time < notAfter), hostname verification against the Subject Alternative Name extension, and revocation checking via CRL or OCSP. Common misconfigurations include serving incomplete certificate chains—the server MUST send the complete chain excluding only the root CA, which clients already trust.

**OCSP stapling eliminates 30%+ latency overhead** from traditional revocation checking. Without stapling, browsers make separate connections to CA OCSP responders, adding round-trips and creating privacy concerns as CAs observe which sites users visit. With stapling enabled, the server periodically fetches signed OCSP responses and includes them in TLS handshakes. This improves privacy by eliminating CA surveillance, reduces latency by removing extra connections, and increases reliability by caching responses server-side.

Certificate Transparency provides detection of mis-issued certificates. Since April 2018, Chrome requires all certificates to appear in public CT logs with Signed Certificate Timestamps (SCTs). Browsers verify SCTs during handshakes, rejecting certificates lacking transparency proof. This prevents rogue CAs from secretly issuing certificates for domains they don't control, as all certificates become publicly auditable at crt.sh and similar services.

## Server Name Indication: Virtual hosting at scale

SNI solves a fundamental TLS limitation: **servers must present certificates before knowing which domain clients request**. Without SNI, hosting multiple HTTPS sites on a single IP address becomes impossible—each domain requires dedicated IP space or error-prone wildcard certificates. SNI extends the TLS protocol by adding a server_name field to the ClientHello message, transmitted in plaintext before encryption begins. This allows servers to select the appropriate certificate based on the requested hostname.

The protocol operates at the TLS handshake level. During ClientHello, the client includes an SNI extension (type code 0) containing the fully qualified DNS hostname in ASCII encoding. The server reads this value before presenting its certificate, enabling selection from multiple certificates bound to the same IP address. This unlocks cost-effective virtual hosting at massive scale—cloud providers like Cloudflare serve millions of domains from shared IP addresses using SNI routing.

**Privacy represents SNI's critical weakness**: the hostname transmits in cleartext during handshakes, visible to network observers. This enables censorship (China, Iran, Turkey filter based on SNI values), corporate surveillance, and ISP tracking. Encrypted Client Hello (ECH) addresses this by encrypting sensitive handshake parameters including SNI. ECH uses a dual-ClientHello architecture: ClientHelloOuter contains public information and a public server name (like cloudflare.com), while ClientHelloInner (encrypted via HPKE) contains the real SNI and sensitive extensions. Chrome and Firefox enabled ECH by default in 2023, requiring DNS-over-HTTPS for public key distribution via HTTPS/SVCB DNS records.

Legacy compatibility remains a consideration. Clients without SNI support (Windows XP, Android pre-2.3, ancient embedded devices) cannot specify hostnames during handshakes. Servers should configure fallback default certificates for these clients, though their market share approaches zero in 2025. More relevant: direct IP address connections lack hostnames, requiring separate handling. Wildcard certificates (*.example.com) work with SNI but only match single subdomain levels—*.example.com matches api.example.com but not deep.api.example.com.

## Certificate management lifecycle

**Modern certificate lifecycles default to 90 days**, driven by Let's Encrypt's automation-first philosophy. Short lifetimes reduce compromise windows and force proper automation, preventing the manual renewal chaos that plagued annual certificates. The CA/Browser Forum now mandates maximum 398-day validity (13 months) for publicly trusted certificates, down from multi-year certificates common before 2020. This shift fundamentally changes operational practices—manual certificate management becomes untenable at 90-day renewal cycles.

Certificate storage security requires strict permissions. Private keys must be readable only by the service account: `chmod 400` or `chmod 600` with `chown root:root` on Linux systems. Store keys in dedicated directories with `chmod 700` permissions, separate from world-readable certificate directories. For high-value keys, Hardware Security Modules (HSMs) provide tamper-resistant storage with FIPS 140-2 Level 3/4 compliance. Cloud providers offer managed HSMs: AWS CloudHSM, Azure Key Vault Premium, Google Cloud HSM. These prevent private key extraction even by administrators with root access.

**Automated rotation at 30 days before expiry** provides 30-day buffer for failure recovery with 90-day certificates. This timing allows two renewal attempts before expiration: initial attempt at 60 days into the 90-day lifetime, with daily retries if necessary. ACME Renewal Info (ARI) further optimizes this by providing server-specified renewal windows exempt from rate limits. Zero-downtime rotation techniques include load balancer certificate overlap (add new certificate while old remains valid), hot reload (Nginx `nginx -s reload`, Apache `apachectl graceful`), and canary deployments (5% → 25% → 50% → 100% server rollout).

Certificate chains require complete intermediate certificates. Servers MUST send end-entity certificate, all intermediates, but NOT the root CA (clients already trust roots). Common misconfiguration: serving only the leaf certificate, causing "unable to get local issuer certificate" errors in OpenSSL-based clients. While Chrome fetches missing intermediates via Authority Information Access (AIA) extensions, curl and many API clients do not. Verify chains: `openssl s_client -connect example.com:443 -showcerts` should show multiple certificates with "Verify return code: 0 (ok)".

Key generation algorithms balance compatibility and performance. **RSA 2048-bit remains the compatibility standard**, supported universally but requiring larger certificates and slower operations. RSA 3072-bit provides post-2030 security but increases computational overhead. **ECDSA P-256 offers equivalent security with 50% smaller certificates** and faster signing, ideal for mobile and IoT. Ed25519 provides best performance but lower legacy compatibility. For general web use, deploy dual certificate configuration: ECDSA P-256 as primary with RSA 2048 fallback for legacy clients. Generate keys: `openssl ecparam -genkey -name prime256v1 -out private.key` for ECDSA, `openssl genrsa -out private.key 2048` for RSA.

## ACME protocol: Automated certificate management

The ACME protocol (RFC 8555) automates the complete certificate lifecycle: account creation, domain authorization, challenge validation, certificate issuance, and renewal. Let's Encrypt issues over 340,000 certificates per hour using ACME, making it the largest CA by certificate count. The protocol uses JSON Web Signature (JWS) for all requests, ensuring authenticity and integrity. Every request includes a replay-prevention nonce, the exact request URL for integrity protection, and account identification via "kid" (key ID) field.

**The complete ACME workflow flows through seven phases**. First, create an account by generating an ES256 or EdDSA key pair and POSTing to /acme/new-account with contact information and terms of service agreement. Second, submit an order to /acme/new-order specifying up to 100 DNS names or IP addresses. Third, fetch authorizations from the order, each providing multiple challenge options. Fourth, fulfill one challenge per authorization—HTTP-01, DNS-01, or TLS-ALPN-01. Fifth, notify the server by POSTing empty JSON to the challenge URL. Sixth, after all authorizations become valid, finalize by submitting a Certificate Signing Request (CSR) to the order's finalize URL. Seventh, download the issued certificate chain from the certificate URL.

### Challenge types and selection strategy

HTTP-01 challenges require serving a specific file at `http://DOMAIN/.well-known/acme-challenge/TOKEN` containing token concatenated with base64url-encoded SHA256 hash of the account public key. The ACME server fetches this file from multiple network vantage points over port 80 (mandatory, no alternatives). **HTTP-01 works for standard websites but cannot issue wildcard certificates** and requires port 80 accessible from the internet. Best for single-server deployments with public web servers.

DNS-01 challenges require creating TXT records at `_acme-challenge.DOMAIN` containing base64url-encoded SHA256 hash of the key authorization. This challenge type enables wildcard certificate issuance (*.example.com), works without public web servers, functions behind firewalls, and supports multi-server environments easily. **DNS-01 remains the only method for wildcards**. Challenges: requires DNS provider API access, subject to DNS propagation delays (seconds to hours), and exposes sensitive DNS API credentials. Use DNS-01 for wildcard certificates, CDN/proxy scenarios, internal domains, and when port 80 is unavailable.

TLS-ALPN-01 operates at the TLS layer by requiring servers to present self-signed certificates containing specific acmeIdentifier extensions when clients negotiate the "acme-tls/1" ALPN protocol on port 443. This challenge enables validation when port 80 is blocked but 443 remains accessible, suitable for TLS-terminating proxies. Limited adoption due to implementation complexity and lack of client library support—HTTP-01 or DNS-01 preferred in most scenarios.

### Rate limits and operational considerations

Let's Encrypt enforces multiple rate limit categories. **Certificates per Registered Domain**: 50 per 7 days (refills 1 per 202 minutes), overridable for hosting providers. **New Orders per Account**: 300 per 3 hours (refills 1 per 36 seconds), overridable. **Duplicate Certificates** (identical identifier set): 5 per 7 days (refills 1 per 34 hours), NOT overridable. **Authorization Failures per Identifier**: 5 per hour, NOT overridable. **Consecutive Authorization Failures**: 1,152 maximum (refills 1 per day, resets on success), NOT overridable.

**ACME Renewal Info (ARI) exempts renewal requests from ALL rate limits**, making it the preferred renewal method. Query the /acme/renewal-info/{certID} endpoint at least twice daily to receive optimal renewal windows. Renewals using the same identifier set also bypass New Orders and Certificates per Domain limits (but remain subject to Duplicate Certificates and Authorization Failures). This enables high-volume hosting providers to renew millions of certificates without hitting limits.

Staging environment testing proves critical: use https://acme-staging-v02.api.letsencrypt.org/directory for all development and testing. Staging provides 30,000 certificates per week vs 50 production, 1,500 new orders per 3 hours vs 300 production. Certificates from staging are NOT browser-trusted (use for automated testing only). Common pitfall: testing against production accidentally, consuming precious rate limit quota and potentially triggering authorization failure lockouts.

Account key management requires careful handling. Generate ES256 (ECDSA P-256) or EdDSA keys for ACME accounts—RSA 2048+ works but is not recommended. Store account keys separately from certificate keys. The account key identifies your account in all ACME operations via "kid" in JWS headers. Key rollover uses a clever double-JWS structure: inner JWS signed by NEW key (containing account URL and old public key), outer JWS signed by OLD key (containing inner JWS). This atomic operation prevents any service interruption during key rotation.

## Haskell TLS implementation guide

The Haskell TLS ecosystem provides pure Haskell implementations avoiding OpenSSL dependencies. The core `tls` library (version 2.1.13) supports TLS 1.2 and 1.3, implements modern cipher suites (AES-GCM, ChaCha20-Poly1305), and provides SNI, ALPN, session resumption, and Encrypted Client Hello support. The library underwent breaking changes in version 2.x, switching from cryptonite to crypton and removing data-default dependency. All applications should use TLS 1.2 as minimum with TLS 1.3 preferred.

### Basic TLS client implementation

```haskell
{-# LANGUAGE OverloadedStrings #-}
import Network.TLS
import Network.TLS.Extra.Cipher
import Network.Socket
import Data.Default.Class

tlsClient :: HostName -> ServiceName -> IO ()
tlsClient hostname port = do
  -- Create TCP socket
  addr:_ <- getAddrInfo Nothing (Just hostname) (Just port)
  sock <- socket (addrFamily addr) Stream defaultProtocol
  connect sock (addrAddress addr)

  -- Configure TLS parameters
  let params = (defaultParamsClient hostname "")
        { clientSupported = def
            { supportedCiphers = ciphersuite_default
            , supportedVersions = [TLS13, TLS12]
            , supportedGroups = [X25519, P256]
            }
        , clientShared = def
            { sharedCAStore = systemStore
            }
        }

  -- Perform handshake
  ctx <- contextNew sock params
  handshake ctx

  -- Send HTTP request
  sendData ctx "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
  response <- recvData ctx
  print response

  -- Clean shutdown
  bye ctx
  close sock
```

The `tls` library provides predefined cipher suite configurations: `ciphersuite_default` includes recommended strong ciphers, `ciphersuite_strong` restricts to only strongest (PFS + AEAD + SHA2), and `ciphersuite_all` includes legacy ciphers (avoid in production). **Always specify supportedVersions explicitly** to prevent TLS 1.0/1.1 usage. System certificate stores integrate via `sharedCAStore = systemStore`, using the operating system's trusted root certificates.

### HTTPS server with warp-tls

```haskell
{-# LANGUAGE OverloadedStrings #-}
import Network.Wai
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS
import qualified Network.TLS as TLS
import Network.TLS.Extra.Cipher

app :: Application
app _ respond =
  respond $ responseLBS status200
    [("Content-Type", "text/plain")
    ,("Strict-Transport-Security", "max-age=31536000; includeSubDomains")]
    "Secure HTTPS Server"

main :: IO ()
main = do
  let tlsConfig = (tlsSettings "certificate.pem" "key.pem")
        { tlsAllowedVersions = [TLS.TLS13, TLS.TLS12]
        , tlsCiphers = ciphersuite_strong
        , onInsecure = DenyInsecure "HTTPS required"
        }

      warpConfig = defaultSettings
        & setPort 443
        & setHost "0.0.0.0"

  putStrLn "HTTPS server on :443"
  runTLS tlsConfig warpConfig app
```

Warp-TLS (version 3.4.13) provides production-ready HTTPS servers with HTTP/2 support via ALPN negotiation. The `tlsSettings` function loads certificate and key files, while `tlsAllowedVersions` restricts protocol versions. Setting `onInsecure = DenyInsecure "message"` rejects plain HTTP connections with a clear error message. For SNI multi-domain hosting, use `tlsSettingsSni` with a function returning appropriate credentials per hostname.

### Certificate validation with x509

```haskell
{-# LANGUAGE OverloadedStrings #-}
import Data.X509
import Data.X509.Validation
import Data.X509.CertificateStore
import System.X509

validateCertificate :: FilePath -> HostName -> IO Bool
validateCertificate certFile hostname = do
  -- Load certificate chain
  certs <- readSignedObject certFile
  let chain = CertificateChain certs

  -- Get system CA store
  store <- getSystemCertificateStore

  -- Validate with default checks
  let cache = exceptionValidationCache []
  failures <- validateDefault store cache (hostname, ":443") chain

  case failures of
    [] -> putStrLn "✓ Certificate valid" >> return True
    errs -> do
      putStrLn "✗ Certificate validation failed:"
      mapM_ (putStrLn . ("  " ++) . show) errs
      return False
```

The `x509` library (version 1.7.7) parses X.509 certificates, while `x509-validation` (1.6.12) performs chain validation. The `validateDefault` function implements complete RFC 5280 validation: cryptographic signature verification, validity period checks, hostname matching via Subject Alternative Names, CA constraints, and key usage verification. Custom validation hooks enable certificate pinning or specialized trust models.

### ACME certificate automation workflow

```haskell
import System.Process
import System.Directory
import Control.Monad

data CertConfig = CertConfig
  { domains :: [String]
  , webroot :: FilePath
  , accountKey :: FilePath
  , domainKey :: FilePath
  , certFile :: FilePath
  }

initializeKeys :: CertConfig -> IO ()
initializeKeys cfg = do
  accountExists <- doesFileExist (accountKey cfg)
  domainExists <- doesFileExist (domainKey cfg)

  unless accountExists $
    callCommand $ "openssl genrsa 4096 > " ++ accountKey cfg

  unless domainExists $
    callCommand $ "openssl genrsa 4096 > " ++ domainKey cfg

requestCert :: CertConfig -> IO ()
requestCert cfg = do
  let cmd = unwords
        [ "hasencrypt -D"
        , "-w", webroot cfg
        , "-a", accountKey cfg
        , "-d", domainKey cfg
        , unwords (domains cfg)
        , ">", certFile cfg
        ]
  callCommand cmd

renewCert :: CertConfig -> IO Bool
renewCert cfg = do
  exists <- doesFileExist (certFile cfg)
  if exists
    then do
      let cmd = unwords
            [ "hasencrypt -D"
            , "-w", webroot cfg
            , "-a", accountKey cfg
            , "-d", domainKey cfg
            , "-r", certFile cfg
            , unwords (domains cfg)
            ]
      exitCode <- system cmd
      return $ exitCode == ExitSuccess
    else do
      requestCert cfg
      return True
```

**Hasencrypt provides the most mature Haskell ACME client**, supporting HTTP-01 challenges with automatic renewal. The `-D` flag selects Let's Encrypt production, empty `-D` uses production, omitting `-D` uses staging. The `-r` flag enables smart renewal (only renews if certificate expires soon). Schedule renewal checks with cron: `0 2 * * * hasencrypt -D -w /var/www -a account.pem -d domain.pem -r cert.pem example.com`. After successful renewal, reload web servers: `nginx -s reload` or `systemctl reload nginx`.

For DNS-01 challenges and wildcard certificates, integrate with DNS provider APIs. Popular providers with Haskell support include Cloudflare (via cloudflare-api package), Route53 (via amazonka), and DigitalOcean (via digitalocean package). Create TXT records at _acme-challenge.domain.com with the challenge value, wait for DNS propagation, then notify the ACME server. Clean up old TXT records to prevent response size issues.

## Security best practices for production

**HSTS deployment requires staged rollout to prevent lockout scenarios**. Start with short max-age (300 seconds) for testing, monitoring all resources load over HTTPS. Increase to 1 week (604800), then 1 month (2592000) while monitoring logs. Finally deploy long-term policy: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`. The 2-year max-age provides strong security while includeSubDomains applies policy to all subdomains (ensure ALL subdomains support HTTPS first). The preload directive signals consent for inclusion in browser hardcoded lists, providing protection on first visit but nearly irreversible—test thoroughly for 3-6 months before preload submission.

OCSP stapling configuration eliminates 30%+ handshake latency by caching revocation responses server-side. **Enable in Nginx**: `ssl_stapling on; ssl_stapling_verify on; ssl_trusted_certificate /path/to/chain.pem; resolver 8.8.8.8;`. **Enable in Apache**: `SSLUseStapling on; SSLStaplingCache "shmcb:/var/run/ocsp(128000)"`. Verify with `openssl s_client -connect example.com:443 -status -tlsextdebug`, looking for "OCSP Response Status: successful". The server fetches signed OCSP responses periodically and includes them in TLS handshakes, improving privacy (CA no longer observes site visits), reducing latency (no client→OCSP connection), and increasing reliability (cached responses insulate from OCSP server outages).

Modern security headers provide defense-in-depth. **Content-Security-Policy** prevents XSS attacks: `default-src 'self'; script-src 'self' 'unsafe-inline' cdn.example.com`. **X-Frame-Options** prevents clickjacking: `DENY` or `SAMEORIGIN`. **X-Content-Type-Options** prevents MIME sniffing: `nosniff`. **Referrer-Policy** controls referrer information: `strict-origin-when-cross-origin`. **Permissions-Policy** restricts feature access: `geolocation=(), camera=(), microphone=()`. Deploy these alongside HSTS for comprehensive security.

Certificate pinning (HPKP) is deprecated and removed from all major browsers as of 2020 due to operational risks—misconfiguration causes permanent lockout until max-age expires with no recovery mechanism. Modern alternatives include Expect-CT (transitional, reports violations), Certificate Transparency monitoring (detect unauthorized issuance), and application-level pinning for mobile apps. For web services, rely on proper certificate validation and CT monitoring rather than pinning.

## Production deployment security checklist

### TLS Configuration
- **Disable vulnerable protocols**: SSLv2, SSLv3, TLS 1.0, TLS 1.1 completely
- **Enable modern protocols**: TLS 1.2 (minimum), TLS 1.3 (preferred)
- **Configure strong ciphers**: ECDHE/DHE + AES-GCM/ChaCha20-Poly1305 only
- **Enable server cipher preference**: Prevent client-forced downgrades
- **Use strong DH parameters**: Minimum 2048-bit, prefer 3072-bit or X25519
- **Configure ALPN**: Enable HTTP/2 negotiation for performance

### Certificate Management
- **Use short-lived certificates**: 90-day maximum, prefer automated renewal
- **Set renewal at 30 days**: Provides buffer for failure recovery
- **Deploy complete chains**: End-entity + intermediates, exclude root
- **Enable OCSP stapling**: Cache revocation responses server-side
- **Monitor expiration**: Alert at 30/15/7 days before expiry
- **Use strong key algorithms**: RSA 2048+ or ECDSA P-256+, prefer ECDSA
- **Secure private keys**: Filesystem permissions 400/600, consider HSM for high-value keys

### ACME Automation
- **Test in staging first**: Use staging environment for all development
- **Implement ARI**: Query renewal-info endpoints for rate-limit-exempt renewals
- **Handle failures gracefully**: Exponential backoff, comprehensive logging
- **Choose appropriate challenge**: HTTP-01 for standard, DNS-01 for wildcards
- **Monitor rate limits**: Track consumption, implement client-side limiting
- **Automate completely**: Renewal, deployment, monitoring—no manual steps

### Security Headers
- **HSTS**: max-age=63072000; includeSubDomains; preload (after testing)
- **CSP**: Restrictive Content-Security-Policy preventing XSS
- **X-Frame-Options**: DENY or SAMEORIGIN preventing clickjacking
- **X-Content-Type-Options**: nosniff preventing MIME confusion
- **Referrer-Policy**: strict-origin-when-cross-origin limiting leakage

### Monitoring and Testing
- **Certificate transparency**: Monitor CT logs at crt.sh for unauthorized issuance
- **SSL Labs scan**: Regular A+ rating validation at ssllabs.com/ssltest
- **Expiration monitoring**: Automated checks, Prometheus alerts, CloudWatch alarms
- **Log all operations**: Certificate requests, renewals, failures, rotations
- **Test regularly**: Quarterly disaster recovery drills, renewal failure scenarios

### Incident Response
- **Document procedures**: Key compromise response, certificate revocation process
- **Maintain backups**: Encrypted private key backups in multiple secure locations
- **Plan rollback**: Keep previous certificates available for emergency rollback
- **Test recovery**: Quarterly restoration drills, verify backup integrity

## Common vulnerabilities and mitigations

**POODLE** (Padding Oracle On Downgraded Legacy Encryption, 2014) exploited SSL 3.0 CBC padding validation, allowing plaintext recovery through 256 requests per byte. Mitigation: Disable SSL 3.0 completely, reject TLS_FALLBACK_SCSV downgrade attempts.

**BEAST** (Browser Exploit Against SSL/TLS, 2011) attacked TLS 1.0 CBC ciphers through chosen-plaintext attacks on initialization vectors. Mitigation: Disable TLS 1.0, prefer TLS 1.2+ with AEAD ciphers (GCM, ChaCha20-Poly1305).

**CRIME** (Compression Ratio Info-leak Made Easy, 2012) and **BREACH** (2013) extracted secrets through TLS/HTTP compression side channels. Mitigation: Disable TLS compression, carefully evaluate HTTP compression for sensitive data.

**Heartbleed** (2014) exploited OpenSSL heartbeat extension buffer over-read, leaking memory contents including private keys. Mitigation: Update OpenSSL immediately (1.0.1g+), rotate potentially compromised keys, monitor for unauthorized certificate issuance.

**FREAK** (Factoring RSA Export Keys, 2015) and **Logjam** (2015) forced weak export-grade cryptography through protocol implementation flaws. Mitigation: Disable export ciphers completely, use strong DH parameters (2048-bit minimum), prefer ECDHE over DHE.

**DROWN** (Decrypting RSA with Obsolete and Weakened eNcryption, 2016) enabled cross-protocol attacks when servers supported both SSLv2 and modern TLS with same keys. Mitigation: Disable SSLv2 on ALL servers using the same keys, never reuse keys across protocols.

**ROBOT** (Return Of Bleichenbacher's Oracle Threat, 2017) resurged Bleichenbacher padding oracle attacks against RSA key exchange. Mitigation: Disable RSA key exchange cipher suites, use only ECDHE/DHE with forward secrecy.

**Sweet32** (2016) exploited 64-bit block ciphers (3DES, Blowfish) through birthday attacks after 32GB traffic. Mitigation: Disable 3DES completely, use 128-bit+ block ciphers (AES).

## Implementation patterns for Haskell applications

### HTTP client with custom validation

```haskell
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Network.Connection
import qualified Network.TLS as TLS

customTlsManager :: IO Manager
customTlsManager = do
  let tlsParams = (TLS.defaultParamsClient "example.com" "")
        { TLS.clientSupported = def
            { TLS.supportedCiphers = ciphersuite_strong
            , TLS.supportedVersions = [TLS.TLS13, TLS.TLS12]
            }
        , TLS.clientHooks = def
            { TLS.onServerCertificate = customValidation
            }
        }
      tlsSettings = TLSSettings tlsParams

  newManager $ mkManagerSettings tlsSettings Nothing

customValidation :: CertificateStore -> ValidationCache -> ServiceID
                 -> CertificateChain -> IO [FailedReason]
customValidation store cache sid chain = do
  -- Perform standard validation
  failures <- validateDefault store cache sid chain

  -- Add custom checks (certificate pinning, etc.)
  if null failures
    then return []
    else return failures
```

### SNI-based virtual hosting

```haskell
import Network.Wai.Handler.WarpTLS
import qualified Network.TLS as TLS

loadCredentials :: HostName -> IO TLS.Credential
loadCredentials hostname = do
  let certFile = "certs/" ++ hostname ++ ".crt"
      keyFile = "certs/" ++ hostname ++ ".key"
  either error id <$> TLS.credentialLoadX509 certFile keyFile

main :: IO ()
main = do
  let tlsConfig = tlsSettingsSni
        (return $ Just loadCredentials)
        "default.crt"
        "default.key"

  runTLS tlsConfig defaultSettings app
```

### Session resumption for performance

```haskell
import Network.TLS
import Data.IORef

setupSessionManager :: IO SessionManager
setupSessionManager = do
  sessions <- newIORef Map.empty

  return SessionManager
    { sessionResume = \sessionID -> do
        cache <- readIORef sessions
        return $ Map.lookup sessionID cache

    , sessionEstablish = \sessionID sessionData -> do
        modifyIORef' sessions (Map.insert sessionID sessionData)

    , sessionInvalidate = \sessionID -> do
        modifyIORef' sessions (Map.delete sessionID)
    }

clientWithResumption :: HostName -> IO ()
clientWithResumption hostname = do
  manager <- setupSessionManager

  let params = (defaultParamsClient hostname "")
        { clientShared = def
            { sharedSessionManager = manager
            }
        }
  -- Subsequent connections reuse sessions
```

## Conclusion: Building secure TLS infrastructure

Modern TLS infrastructure demands automation, monitoring, and defense-in-depth. TLS 1.3 provides mandatory forward secrecy, simplified cipher selection, and improved performance through 1-RTT handshakes. ACME automation eliminates manual certificate management, while short-lived 90-day certificates reduce compromise windows. HSTS prevents protocol downgrades, OCSP stapling improves privacy and performance, and comprehensive monitoring prevents outages.

The Haskell ecosystem provides production-ready TLS implementations through pure Haskell libraries avoiding OpenSSL dependencies. The tls library supports modern protocols and cipher suites, warp-tls enables high-performance HTTPS servers, and hasencrypt automates ACME certificate acquisition. Integration patterns enable custom validation, session resumption, and SNI-based virtual hosting.

Security requires vigilance: disable TLS 1.0/1.1, enforce strong cipher suites, implement HSTS with careful rollout, enable OCSP stapling, monitor Certificate Transparency logs, and maintain comprehensive incident response procedures. Test configurations with SSL Labs, automate renewal with ARI-based scheduling, and rehearse failure scenarios quarterly. With proper implementation, TLS infrastructure provides confidentiality, integrity, and authenticity for modern production systems.
