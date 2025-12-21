---
stand_alone: true
category: std
submissionType: IETF
ipr: trust200902
lang: en
title: Automated Certificate Management Environment (ACME) rats Identifier and Challenge Type
abbrev: acme-rats
docname: draft-ietf-acme-rats-latest
area: "Security"
workgroup: "Automated Certificate Management Environment"
kw:
 - ACME
 - RATS
 - Zero Trust
venue:
  group: "Automated Certificate Management Environment"
  type: "Working Group"
  mail: "acme@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/acme/"
  github: "liuchunchi/draft-liu-acme-rats"
  latest: "https://liuchunchi.github.io/draft-liu-acme-rats/draft-liu-acme-rats.html"
author:
 -
    fullname: Chunchi Peter Liu
    organization: Huawei
    email: liuchunchi@huawei.com
 -
    fullname: Mike Ounsworth
    email: mike@ounsworth.ca
 -
    fullname: Michael Richardson
    organization: Sandelman Software Works Inc
    email: mcr+ietf@sandelman.ca
normative:
  RFC8555:
  RFC9334:
  I-D.ietf-rats-msg-wrap: CMW
  I-D.ietf-rats-ar4si: AR4SI
informative:
  CSRATT: I-D.ietf-lamps-csr-attestation
  RATSPA: I-D.ietf-rats-posture-assessment
  RATSKA: I-D.ietf-rats-pkix-key-attestation
  I-D.draft-bweeks-acme-device-attest-01: device-attest-01
  letsencrypt:
    target:    https://www.eff.org/deeplinks/2023/08/celebrating-ten-years-encrypting-web-lets-encrypt
    title: "Celebrating Ten Years of Encrypting the Web with Let's Encrypt"
    author:
      org:
      - "Electronic Frontier Foundation"
    date: 2025-08-20
  CABF-CSBRs:
    target: https://cabforum.org/working-groups/code-signing/documents/
    title: "Baseline Requirements for Code-Signing Certificates"
    author:
      org:
      - CA/BROWSER FORUM

--- abstract

This document describes an approach where an ACME Server can challenge an ACME Client to provide a Remote Attestation Evidence or Remote Attestation Result in any format supported by the Conceptual Message Wrapper.

The ACME Server can optionally challenge the Client for specific claims that it wishes attestation for.

--- middle

# Introduction

ACME {{RFC8555}} is a standard protocol for issuing and renewing certificates automatically.
When an ACME client needs a certificate, it connects to the ACME server, providing a proof of control of a desired identity. Upon success, it then receives a certificate with that identity in it.

These identities become part of the certificate, usually a Fully Qualified Domain Name (FQDN) that goes into the Subject Alt Name (SAN) for a certificate.
Prior to ACME, the authorization process of obtaining a certificate from an operator of a (public) certification authority was non-standard and ad-hoc.
It ranged from sending faxes on company letterhead to answering an email sent to a well-known email address like `hostmaster@example.com`, evolving into a process where some randomized nonce could be placed in a particular place on the target web server.
The point of this process is to prove that the given DNS FQDN was controlled by the client system.

ACME standardized the process, allowing for automation for certificate issuance.
It has been a massive success: increasing HTTPS usage from 27% in 2013 to over 80% in 2019 {{letsencrypt}}.

While the process supports many kinds of identifiers: email addresses, DTN node IDs, and can create certificates for client use.
However, these combinations have not yet become as popular, in part because these types of certificates are usually located on much more general purpose systems such as laptops and computers used by people.

The concern that Enterprises have with the use of client side certificates has been the trustworthiness of the client system itself.
Such systems have many more configurations, and are often considered harder to secure as a result.
While well managed mutual TLS (client and server authentication via PKIX certificate) has significant advantages over the more common login via username/passowrd,  if the private key associated with a client certificates is disclosed or lost, then the impact can be more significant.

The use case envisioned here is that of an enterprise.  A Network Operations Center (NOC)
(which may be internal or an external contracted entity) will issue (client) certificates to devices that can prove via remote attestation that they are running an up-to-date operating system as well as the enterprise-required endpoint security software.

This is a place where Remote Attestation can offer additional assurance {{RFC9334}}.
If the software on the client is properly designed, and is up to date, then it is easier to assure that the private key will be safe.

This can be extended to Bring Your Own Device (BYOD) by having those devices provide an equivalent Attestation Result.

In this document, we propose an approach where ACME Server MAY challenge the ACME Client to produce an Attestation Evidence or Attestation Result in any format that is supported by the RATS Conceptual Message Wrapper {{-CMW}}, for instance, an EAT (entity attestation token).
The ACME Server then verifies the attestation result against an appraisal policy as required by by the requested certificate profile.

ACME can presently offer certificates with multiple identities.
Typically, in a server certificate situation, each identity represents a unique FQDN that would be placed into the certificate as distinct Subject Alt Names (SAN).
For instance each of the names: example.com, www.example.com, www.example.net and marketing.example.com might be placed in a single certificate for a server that provides web content under those four names.

This document defines a new identity type, `trustworthy` that the ACME client can ask for.
A new `attestation-result-01` challenge is defined as a new method that can be used to authorize this identity using a RATS Passport model.
The `attestation-evidence-02` challenge is also defined, enabling a background check mechanism.

In this way, the Certification Authority (CA) or Registration Authority (RA) issues certificates only to devices that can provide an appropriate attestation result, indicating that the device from which the ACME request originates has passed the required security checks.

Attested ACME requests can form an essential building block towards the continuous monitoring/validation requirement of Zero-Trust principle when coupled with other operational measures, such as issuing only short-lived certificates.

For ease of denotion, we omit the "ACME" adjective from now on, where Server means ACME Server and Client means ACME Client.

## Attestation Results only

This document currently only defines the a mechanism to carry Attestation Results from the ACME client to the ACME server.
It limits itself to the Passport model defined in {{RFC9334}}.

This is done to simplify the combinations, but also because it is likely that the Evidence required to make a reasonable assessment includes potentially privacy violating claims.
This is particularly true when a device is a personal (BYOD) device; in that case the Verifier might not even be owned by the Enterprise,  but rather the device manufacturer.

In order to make use of the background check that Evidence would need to be encrypted from the Attesting Environment to the Verifier, via the ACME Server -- the Relying Party.
Secondly, in order for the ACME Server to be able to securely communicate with an Enterprise located Verifier with that Evidence, then more complex trust relationships would need to be established.
Thirdly, the Enterprise Verifier system would then have to expose itself to the ACME Server, which may be located outside of the Enterprise.
The ACME Server, for resiliency and loading reasons may be a numerous and dynamic cluster of systems, and providing appropriate network access controls to enable this communication may be difficult.

Instead, the use of the Passport model allows all Evidence to remain within an Enterprise,
and for Verifier operations to be more self-contained.

## Related work

{{CSRATT}} define trustworthy claims about the physical storage location of a key pair's private key.
This mechanism only relates to how the private key is kept.
It does not provide any claim about the rest of the mechanisms around access to the key.
A key could well be stored in the most secure way imaginable, but in order to use the key some command mechanism must exist to invoke it.

The mechanism created in this document allows certification authority to access the trustworthiness of the entire system.
That accessment goes well beyond how and where the private key is stored.
ACME uses Certificate Signing Requests, so there is no reason that {{CSRATT}} could not be combined with the mechanism described in this document.

{{RATSPA}} defines a summary of a local assessment of posture for managed systems and across various  layers.
The claims and mechanisms defined in {{RATSPA}} are a good basis for the assessment that will need to be done in order to satisfy the trustworthiness challenge detailed in this document.

# ACME Extensions


## 'rats' identifier

A new identifier type to indicate client support or server request for remote attestation.
This is a "dummy" identifier in that the `value` does not contain an actual identifier, but instead a property that is the be remotely attested.
The `value` MAY be left empty, or contain a property hint as per {{prophints}}.

type (required, string):
: The string "rats".

value (required, string):
: A string from the  ACME Attest Claims Hint Registry defined in {{prophints}}, which could be the empty string.

A Server MAY issue challenges for multiple "rats" identifiers in the same ACME protocol flow.

The Client MUST complete the challenge by returning a CMW {{-CMW}} which MAY contain remote attestation data in any format (EAT (cite), WebAuthn (cite), TPM attest_certify (cite), PKIXKeyAttesation (cite), proprietary, etc), and of any RATS conceptual message type (evidence, endorsement, or attestation result). This document does not remove the need for vendors to perform interoperability testing with CAs to ensure compatibility.

## remote-attest-01 Challenge {#rats-chall}

A `remote-attest-01` challenge type asks the Client to prove provide remote attestation. The Client SHOULD use the provided
`freshness_nonce` as an attestation freshness nonce, if the Client's underlying attestation technology supports freshness nonces.

The Server MAY include a `attestClaimsHint` containing a list of claims that it would like to see in the

This section describes the challenge/response extensions and procedures to use them.

### remote-attest-01 Challenge Object

The `remote-attest-01` Challenge Object is:

The basic fields `type` (which MUST be "remote-attest-01"), `url`, `status`, `validated` and `error` are preserved from {{Section 8 of RFC8555}} un-modified. The following new fields are added:

freshness_nonce (required, string):
: A randomly created nonce provided by the server which MUST be included in the Attestation Results to provide freshness.
EDNOTE TODO: we should decide whether this nonce MAY / SHOULD / SHOULD NOT / MUST NOT be the same as the ACME nonce or the ACME Challenge URL.

attestClaimsHint (optional, list of string)
: If the Server requires attestation of specific claims or properties in order to issue the requested certificate profile, then it MAY list one or more types of claims from the newly-defined ACME Attest Claims Hints registry defined in {{prophints}}.

verifierEncryptionCredential (optional, string url)
: A URL where the Client can fetch the encryption public key that it can use for encrypting the rats challenge response.


The `attestClaimsHint` SHOULD contain values from the "JSON Web Token Claims" registry created by {{!RFC7519}}, in particular claims related to remote attestation as registered in {{!RFC9711}} and related documents, but MAY contain non-registered values. The Client SHOULD attempt to collect evidence, endorsements, or attestation results from its local environment that satisfies these claims, either directly if the local environment supports EAT {{!RFC7519}}, or mapped to the closest equivalent claims in the supported format. The Client MAY ignore any claims that it does not recognize or that it is unable to collect remote attestation for. In other words, the Client SHOULD return what it has rather than failing, and allow the Server to decide if it is acceptable for the requested certificate profile.

The `verifierEncryptionCredential` is for cases where the evidence contains sensitive data, such as identifiers that could be linkable to a person and therefore qualify as Personally Identifiable Information and the Client wishes to protect it against accidental logging, for example by HTTP proxies, as it passes through the Server's application stack. The design of passing a URL to the encryption public key as part of the `remote-attest-01` challenge object allows the Server to manage multiple verifierEncryptionCredentials, and choose the one appropriate to this certificate request flow. The `verifierEncryptionCredential` URL SHOULD be a semi-static UUID-style URL so that the Client can create a cache of previously-fetched encryption credentials, indexed by the path component of the `verifierEncryptionCredential` URL. The Server MAY, for example, use the public key fingerprint as the path component in the `verifierEncryptionCredential` URL. The referenced credential SHOULD be in the JSON Web Key (JWK) {{!RFC7517}} format, but MAY be in other reasonable formats such as a DER or PEM encoded X.509 certificate.

EDNOTE: in the name of simplicity, make this "MUST JWK"?



### remote-attest-01 Response {#attestation-response}

The HTTP POST body to the challenge URL MUST be a raw JSON or CBOR CMW {{-CMW, Section 5.2}}, base64 encoded as necessary.

If the Server provided a `verifierEncryptionCredential` and the Client wishes to make use of it, then the entire CWM payload MUST be placed inside a JSON Web Encryption (JWE) envelope {{!RFC7516}}.


# Example Protocol Flow

## Step 1: newOrder Request Object {#new-order-req}

During the certificate order creation step, the Client sends a /newOrder JWS request (Section 7.4 of {{RFC8555}}) whose payload contains an array of identifiers. To indicate support for remote attestation, the client adds one or more `rats` identifiers to the array of identifiers. This is entirely optional and the server MAY choose to challenge for attestation or not according to its configuration for the requested certificate profile irrespective of whether the client indicated that it is attestation-capable.

The "rats" identifier MAY appear as the only identifier type in the array, but only if the supported remote attestation type is capable of proving control of the identifier(s) that will go into the certificate's CN or SANs. For example, a secure-boot style remote attestation MAY be capable of proving ownership of a hardware serial number, or a WebAuthn / FIDO / Passkey style remote attestation MAY be capable of proving control of a FIDO token belonging to a given username or email address.
However, more typically the "rats" identifier serves to provide supplemental trustworthiness next to a direct proof-of-control identity challenge such as DNS-01 or HTTP-01.


In this example, a client is requesting a certificate for a `dns` identity `client01.finance.example` and offers that it can provide remote attestation of the secure-boot stack of the application server via the RATS identifier `"secure-boot"`, as well as provide remote attestation from the underlying cryptographic hardware holding the private key via the RATS identifier `"hsm"`. These values refer to the ACME Attest Properties Hint Registry defined in {{prophints}}.

An example extended newOrder JWS request:

~~~~~~~~~~
  POST /acme/new-order HTTP/1.1
  Content-Type: application/json
  {
    "protected": base64url({
      "alg": "ES256",
    }),
    "payload": base64url({
      "identifiers": [
        { "type": "dns", "value": "client01.finance.example" },
        { "type": "rats", "value": "secure-boot" },
        { "type": "rats", "value": "hsm" },
      ],
    }),
    "signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
  }
~~~~~~~~~~


## Step 2: Order Object {#new-order-resp}

As explained in {{RFC8555, Section 7.1.3}}, the server returns an Order Object.

An example extended Order Object that includes RATS challenges is:

~~~~~~~~~~
  POST /acme/new-order HTTP/1.1
  ...

  HTTP/1.1 200 OK
  Content-Type: application/json
  {
    "status": "pending",

    "identifiers": [
        { "type": "dns", "value": "client01.finance.example" },
        { "type": "rats", "value": "secure-boot" },
        { "type": "rats", "value": "hsm" },
    ],

    "authorizations": [
      "https://example.com/acme/authz/PAniVnsZcis",
      "https://example.com/acme/authz/C1uq5Dr+x8GSEJTSKW5B",
      "https://example.com/acme/authz/01jcCDfT0iJBmUlaueum",
    ],

    "finalize": "https://example.com/acme/order/T..fgo/finalize",
  }
~~~~~~~~~~

Note that the URLs listed in the `authorizations` array are arbitrary URLs created by the ACME server.
The last component is a randomly created string created by the server.
For simplicity, the first URL is identical to the example given in {{RFC8555}}.

The server is not required to match the list of RATS identifiers provided by the client. The server MAY challenge for a subset of the RATS identifiers offered by the client, or it MAY challenge for RATS identifiers that were not offered by the client. The server has full discretion for deciding what properties are required to be attested for the requested certificate profile.


## Step 3: Authorization Object

The Client MUST complete the authorizations provided by the server, but it MAY do so in any order {{!RFC8555}}.

In this example, the Server has created an Authorization Object for the "rats" and "dns" identifiers.
The client accesses each authorization object from the URLs given in the Order Object.
In this example, the `PAniVnsZcis` authorization relates to the `dns` identifier, and
it is not changed from {{RFC8555, Section 8}}.
The `C1uq5Dr+x8GSEJTSKW5B` authorization corresponds to the RATS "secure-boot" identifier.

Here is an example `remote-attest-01` challenge:

~~~~~~~~~~
   GET https://example.com/acme/authz/C1uq5Dr+x8GSEJTSKW5B HTTP/1.1
   ..

   HTTP/1.1 200 OK
   Content-Type: application/json
   {
     "status": "pending",
     "expires": "2025-09-30T14:09:07.99Z",

     "identifier": {
       "type": "rats",
       "value": "secure-boot"
     },

     "challenges": [
       {
         "type": "remote-attest-01",
         "url": "https://example.com/acme/chall/prV_8235AD9d",
         "status": "pending",
         "freshness_nonce": "yoW1RL2zPBzYEHBQ06Jy",
         "attestClaimsHint": ["hwmodel", "swversion", "submods", "manifests",],
         "verifierEncryptionCredential": "https://example.com/acme/rats-encr-keys/_fyg_W85yTul8zDPygcIgKmj-xA",
       }
     ],
   }
~~~~~~~~~~

In this example, the Server is indicating that it wants secure-boot type remote attestation including the following claims:

~~~
"attestClaimsHint": ["hwmodel", "swversion", "submods", "manifests",],
~~~

meaning that it is interesting in the type of device and what software is running on it. This field is called a "hint" because the ACME Client might not be capable of obtaining remote attestation evidence, endorsements, or attestation results that directly map to these claims. Servers SHOULD NOT we written to expect exactly these claims back. This mechanism does not remove the need for vendors to perform interop testing against CAs.

EDNOTE: is the attestClaimsHint actually adding anything useful on top of the identifier values of "secure-boot", "hsm", "passkey", etc?



## Step 4: Respond to RATS Challenge

The client now queries its local environment to obtain evidence, endorsements and/or attestation results to satisfy the RATS challenge.

If the underlying remote attestation technology supports a freshness nonce, then the Client passes the (example) token `yoW1RL2zPBzYEHBQ06Jy` into the underlying attestation service as the nonce.

The payload of the RATS Challenge response MUST be a CMW {{-CMW}}, but the underlying payload type within the CMW is left unconstrained and therefore the details of collecting the remote attestation data for this this step are not in scope for this document.
As an example, it might use EAT {{?RFC9711}}, TPM-CHARRA {{?RFC9684}}, or X, or Y (XXX: insert more options)

Assume the following binary blob is RATS evidence collected by the Client:

~~~~~~~~~~
yePAuQj5xXAnz87/7ItOkDTk5Y4syoW1RL2zPBzYEHBQ06JyUvZDYPYjeTqwlPszb9Grbxw0UAEFx5DxObV1
~~~~~~~~~~

This result is sent as a POST to `https://example.com/acme/chall/prV_8235AD9d`

~~~~~~~~~~
   POST https://example.com/acme/chall/prV_8235AD9d HTTP/1.1
   ..
   Content-Type: application/cmw+cbor

   yePAuQj5xXAnz87/7ItOkDTk5Y4syoW1RL2zPBzYEHBQ06JyUvZDYPYjeTqwlPszb9Grbxw0UAEFx5DxObV1
~~~~~~~~~~

(EDIT: change to cwm+jws example that wraps the example binary blob)

Alternatively, the Client MAY use the JWE format {{!RFC7516}} to encrypt the remote attestation data for the Server's `verifierEncryptionCredential` and instead send a POST like this:

~~~~~~~~~~
   POST https://example.com/acme/chall/prV_8235AD9d HTTP/1.1
   ..
   Content-Type: application/jwt

   eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.RYSEVOaD[snip]wwEbtY96_8P3a_A.5QLBf5hAXCkP7CdS.XBiai[snip]RWz1D3f.kCIIMWMoObyekuQ33u0oYQ
~~~~~~~~~~

('\[snip\]' indicates that the JWE has been truncated for publication.)


The Server decodes the provided CMW {{-CMW}}.

The Server MUST perform a full verification of the remote attestation data, including verification of the signature against a pre-configured trust anchor, and appraisal according to a suitable appraisal policy. The CA's certificate policy is the final authority for what trust anchors and appraisal policies will apply and the details are not in scope for this document.

At this point, if the client were to re-retrieve the authorization object from step 3, it would observe (if everything was accepted and successfully verified) that the status for this challenge would now be marked as valid.


## Step 5: Perform other challenges

The client SHOULD now perform any other RATS or non-RATS challenges that were listed in the Order Object from step 2.
ACME provides no ordering constraint on the challenges, so the Client MAY process them in any order, including concurrently.


## Step 6: Finalize Order, retrieve certificate

At this point, the process continues as described in {{Section 7.4 of RFC8555}}.
This means that the finalize action is used, which includes a CSR.
If all is well, it will result in a certificate being issued.


# ACME Attest Properties Hint Registry {#prophints}

In order for the client to communicate in the newOrder request what types of attestation it is capable of producing, and for the server to indicate in the newOrder response what properties it requires attestation of, this specification creates a new IANA registry called "ACME Attest Properties Hint Registry. The hint is used as the value of the "rats" identifier type, as described in {#new-order-req} and {#new-order-resp}. In order to preserve vendor flexibility, the initial values in the ACME Attest Properties Hint Registry are intended to be generic in nature, and decoupled from the RATS conceptual message type (evidence, endorsement, or attestation result) or attestation data format (EAT (cite), WebAuthn (cite), TPM attest_certify (cite), PKIXKeyAttestation (cite), or device-proprietary). This model expects CAs to publish documentation about what specific data formats they support, and for vendors to perform interoperability testing with CAs to ensure compatibility. Ultimately, the CA's certificate policies will be the authority on what evidence or attestation results it will accept.

The ACME Attest Claims Hint Registry is intended to help clients to collect evidence or attestation results that are most likely to be acceptable to the server, but are not a guaranteed replacement for performing interoperability testing between a given attesting device and a given CA. Similarly, an ACME attestation hint may not map one-to-one with attestation functionality exposed by the underlying attesting device, so ACME clients might need to act as intermediaries mapping ACME hints to vendor-specific functionality on a per-hardware-vendor basis.

See {{iana-propshints}} for the initial contents of this new registry.

# Example use cases

## Conflicting duties

(EDIT: This text might be stale)

1. Integration/compatibility difficulty: Integrating SOC and NOC requires plenty of customized, case-by-case developing work. Especially considering different system vendors, system versions, different data models and formats due to different client needs... Let alone possible updates.

2. Conflict of duties: NOC people do not want SOC people to interfere with their daily work, and so do SOC people. Also, NOC people may have limited security knowledge, and SOC people vice versa. Where to draw the line and what is the best tool to help them collaborate is a question.


## Enterprise WiFi Access

In enterprise access cases, security administrators wish to check the security status of an accessing end device before it connects to the internal network.
Endpoint Detection and Response (EDR) softwares can check the security/trustworthiness statuses of the device and produce an Attestation Result (AR) if the check passes. ACME-RATS procedures can then be used to redeem a certificate using the AR.

With that being said, a more specific use case is as follows: an enterprise employee visits multiple campuses, and connects to each one's WiFi. For example, an inspector visits many (tens of) power substations a day, connects to the local WiFi, download log data, proceed to the next and repeat the process.

Current access solution include: 1. The inspector remembers the password for each WiFi, and conduct the 802.1X EAP password-based (PAP/CHAP/MS-CHAPv2) authentication. or 2. an enterprise MDM receives the passwords and usernames over application layer connection from the MDM server, and enter them on user's behalf. While Solution 1 obviously suffer from management burdens induced by massive number of password pairs, and password rotation requirements, the drawback of Solution 2 is more obsecure, which include:

a. Bring Your Own Device (BYOD) situation and MDM is not available.
b. Password could risk leakage due to APP compromise, or during Internet transmission. Anyone with leaked password can access, without binding of trusted/usual devices.
c. The RADIUS Client/Access Point/Switch is not aware of the identity of the accessing device, therefore cannot enforce more fine-grained access policies.

An ideal user story is:
1. When the inspector is at base (or whenever the Remote Attestation-based check is available), he get his device inspected and redeem a certificate using ACME-RATS.
2. When at substation, the inspector authenticate to the WiFi using EAP-TLS, where all the substations have the company root CA installed.
2*. Alternatively, the Step 2 can use EAP-repeater mode, where the RADIUS Client redirects the request back to the RADIUS Server for more advanced checks.

## BYOD devices

Another example is issuing S/MIME certificates to BYOD devices only if they can prove via attestation that they are registered to a corporate MDM and the user they are registered to matches the user for which a certificate has been requested.

In this case, the Server might challenge the client to prove that it is properly-registered to the enterprise to the same user as the subject of the requested S/MIME certificate, and that the device is running the corporate-approved security agents.


## Private key in hardware

In some scenarios the CA might require that the private key corresponding to the certificate request is stored in cryptographic hardware and non-extractable. For example, the certificate profile for some types of administrative credentials may be required to be stored in a token or smartcard. Or the CA might be required to enforce that the private key is stored in a FIPS-certified HSM running in a configuration compliant with its FIPS certificate -- this is the case, for example, with CA/Browser Forum Code Signing certificates {{CABF-CSBRs}} which can be attested for example via [RATSKA].

It could also be possible that the requested certificate profile does not require the requested key to be hardware-backed, but that the CA will issue the certificate with extra assurance, for example an extra policy OID or a longer expiry period, if attestation of hardware can be provided.


# Security Considerations

The attestation-result-01 challenge (the Passport Model) is the mandatory to implement.
The encrypted-evidence-01 challenge (the background-check model) is optional.

In all cases the Server has to be able to verify Attestation Results from the Verifier.
To do that it requires appropriate trust anchors.

In the Passport model, Evidence -- which may contain personally identifiable information (PII)) -- is never seen by the ACME Server.
Additionally, there is no need for the Verifier to accept connections from ACME Server(s).
The Attester/Verifier relationship used in the Passport Model leverages a pre-existing relationship.
For instance if the Verifier is operated by the manufacturer of the Attester (or their designate), then this is the same relationship that would be used to obtain updated software/firmware.
In this case, the trust anchors may also be publically available, but the Server does not need any further relationship with the Verifier.

In the background-check model, Evidence is sent from the Attester to the ACME Server.
The ACME Server then relays this Evidence to a Verifier.
The Evidence is encrypted so that the Server it never able to see any PII which might be included.
The choice of Verifier is more complex in the background-check model.
Not only does ACME Server have to have the correct trust anchors to verify the resulting Attestation Results, but the ACME Server will need some kind of business relationship with the Verifier in order for the Verifier to be willing to appraise Evidence.

The `trustworthy` identifier is not an actual identifier.
It does not result in any specific contents to the certificate Subject or SubjectAltName.

# IANA Considerations

## ACME Attest Properties Hint Registry {#iana-propshints}

IANA is requested to open a new registry, XXXXXXXX

Type: designated expert

The registry has the following columns:

- Property Hint: the string value to be placed within an ACME identifier of type "rats".
- Description: a description of the general property which the client is expected to attest.

The initial registry contents is shown in the table below.

| Property Hint       | Description                  |
|------------------|------------------------------|
| ""               | Empty string. Indicates client support for, or a server request for, attestation without being specific about what type. Typically this means the client will produce whatever remote attestation data it is capable of. |
| "hsm"            | Attestation that the private key associated with this certificate request is stored in cryptographic hardware such as a TPM or PKCS#11 HSM. In the case of PKCS#11 HSMs, the attestation SHOULD contain the PKCs#11 properties of the private key storage, as well as an indication of whether the cryptographic module is operating in FIPS mode. |
| "secure_boot"    | Attestation from the device's onboard secure-boot stack of the device running the application. |
| "os_patch_level" | Attestation to the version or patch level of the device's operating system.             |
| "sw_manifest"    | A manifest list of all software currently running on the device.                        |
| "fido2"          | A request for FIDO2-based user authentication; maybe this is to validate a user identifier directly against the FIDO2 data, or maybe this serves as a second-factor to the CA's certificate pickup flow. |

In general, the target environment that the Server wants to be remotely attested is the environment where the application is running. The "hsm" property is an exception to this because this wants attestation from the cryptographic module instead.

In cases where the ACME client is running on a different host from the application, remote attestation always refers to the application host. In other words, a centralized ACME client MUST fulfill the ACME rats challenge by getting the application server that will ultimately use the certificate to query its local environment for remote attestation, and the ACME client MUST NOT present remote attestation from the host where it is running.

TODO: this is normative text that should move up to the body.

EDNOTE: I am somewhat surprised that a registry like this does not already exist associated with CMW.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
