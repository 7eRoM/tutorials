
# Verifying Embedded PE Signature

# What Do We Cover?

For a given signed PE file, with the signature embedded, we extract the signature and certificates. These are then parsed using PKCS and ASN.1 standards.

# What We Don't Cover

- PE files whose digital signatures are not embedded (reside in catalog files)
- Validating timestamp of the signatures
- Validating the key usage
- Validating the chain of the certificates
- Using Windows APIs like `WinTrust` to verify signatures
- A full tutorial on ASN.1


# Tools

- CFF Explorer
- signtool
- HxD
- pe bear

# Links


# Table of Contents

- Parsing PE
- Parsing WIN_CERTIFICATE
- PKCS #n
- Structure of PKCS #7
- Parsing ContentInfo
- Parsing Certificates
- Parsing SignInfo
- Appendix A: PE Authenticode Hash
- Appendix B: A Brief Introduction to ASN.1
- Appendix C: Most Important Fields


# Introduction

PE files are digitally signed to verify various aspects, such as identifying the publisher of the file and ensuring the file's integrity has not been compromised. In this write-up, we will not explain why PE files are signed, but we will delve into how they are signed and how we can verify their signatures.


## Digital Signature

We provide a sample in the *sample* directory, which contains a file named *dbgview64.exe*. We perform all verification operations on this sample PE file.

In the properties of this PE, we can view the *Digital Signatures* tab.

![Digital Signatures](Images/DigitalSignatures.JPG)

This tab contains almost all the information we need for verification. If we go to *Details*, the information about the signature is displayed.

![Signature Details](Images/SignatureDetails.JPG)

You can see many *fields*—some you may understand, some you may not, and some you might misunderstand. Misunderstand!? Yes, by the end of this write-up, you'll find out!

Next, we go to the *General* tab to view the certificate that signed this PE file and the hierarchy of the certifications.

![General Details](Images/GeneralDetails.JPG)

If we click on *View Certificate* and then go to the *Details* tab, we can find all the information about the signer's certificate for this PE file.

![Certification Details](Images/CertificationDetails.JPG)

Some fields are not part of the certificate and can only be found in the GUI. Unfortunately (!), one of them is the *Thumbprint*, which is calculated every time you open this dialog. Therefore, we must calculate it manually. We discuss this later.

![Thumbprint Details](Images/ThumbprintDetails.JPG)

In the *Certification Path* tab, we can find the chain of certifications. To view the details of each certificate, you can click *View Certificate* as before.

![Certification Chain Details](Images/CertificationChainDetails.JPG)

However, for some PEs, like *C:\Windows\System32\notepad.exe*, the *Digital Signatures* tab does not exist. What does this mean? It means that Notepad is not signed!

Let's check with *signtool.exe*:

```shell
C:\>signtool.exe verify /a /v C:\Windows\System32\notepad.exe

Verifying: C:\Windows\System32\notepad.exe
File is signed in catalog: C:\WINDOWS\system32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-Notepad-FoD-Package~31bf3856ad364e35~amd64~~10.0.19041.4355.cat
Hash of file (sha1): BC43D65CC41670FBB1E1A686AE62BFF3F9AA784A

Signing Certificate Chain:
    Issued to: Microsoft Root Certificate Authority 2010
    Issued by: Microsoft Root Certificate Authority 2010
    Expires:   Sun Jun 24 01:34:01 2035
    SHA1 hash: 3B1EFD3A66EA28B16697394703A72CA340A05BD5

        Issued to: Microsoft Windows Production PCA 2011
        Issued by: Microsoft Root Certificate Authority 2010
        Expires:   Mon Oct 19 22:21:42 2026
        SHA1 hash: 580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D

            Issued to: Microsoft Windows
            Issued by: Microsoft Windows Production PCA 2011
            Expires:   Thu Nov 14 22:50:08 2024
            SHA1 hash: 71F53A26BB1625E466727183409A30D03D7923DF

The signature is timestamped: Sat Apr 13 19:02:25 2024
Timestamp Verified by:
    Issued to: Microsoft Root Certificate Authority 2010
    Issued by: Microsoft Root Certificate Authority 2010
    Expires:   Sun Jun 24 01:34:01 2035
    SHA1 hash: 3B1EFD3A66EA28B16697394703A72CA340A05BD5

        Issued to: Microsoft Time-Stamp PCA 2010
        Issued by: Microsoft Root Certificate Authority 2010
        Expires:   Mon Sep 30 22:02:25 2030
        SHA1 hash: 36056A5662DCADECF82CC14C8B80EC5E0BCC59A6

            Issued to: Microsoft Time-Stamp Service
            Issued by: Microsoft Time-Stamp PCA 2010
            Expires:   Fri Jan 10 22:37:12 2025
            SHA1 hash: 68A0528ACCB8CBCEA997C5F2DB6089644C44DAF3

Successfully verified: C:\Windows\System32\notepad.exe

Number of files successfully Verified: 1
Number of warnings: 0
Number of errors: 0
```

The signature is verified! Which signature?

Don't be confused! Windows stores the signatures of some PE files in the *CatRoot* database (located in `C:\Windows\System32`). Many System32 PE files have their signatures residing in this database. In this write-up, we will not discuss catalog files and how to parse them. Therefore, discussing PE files whose signatures are not embedded within their files is out of our scope.

# Parsing PE

Open *dbgview64.exe* with *CFF Explorer*. In the `Optional Header`, there is a data directory named `Security Directory` (also known as the `Certification Table`).

![Security Directory](Images/SecurityDirectory.JPG)

Also, you can find the `Security Directory`  using *PE Bear* in `Security` tab.

![PE-Bear Security Directory File Offset](Images/PEBearSecurityDirectory.jpg)

This section shows where the embedded digital signature is located and determines its size. For our sample file, it resides at offset `0x10B400` from the beginning of the file with a size of `0x2378`.

![Security Directory File Offset](Images/SecurityDirectoryFileOffset.JPG)

If you look at the decoded text, you can find meaningful words like *Microsoft Corporation*, *Redmond*, *Washington*, etc. It seems we are in the right place.

How can we decode the bytes to accomplish our mission? To decode it, we must be familiar with `WIN_CERTIFICATE`.

So, it's time to get our hands dirty!

# Parsing WIN_CERTIFICATE

All the bytes in the security directory must be interpreted as a `WIN_CERTIFICATE` structure, as shown below:

```cpp
typedef struct _WIN_CERTIFICATE {
  DWORD dwLength;
  WORD  wRevision;
  WORD  wCertificateType;
  BYTE  bCertificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE, *LPWIN_CERTIFICATE;
```

 - **dwLength** (4 bytes): The length of the structure or security directory. As seen in the raw file, it is `23 78 00 00`.
 - **wRevision**: The revision number. Not important here.
 - **wCertificateType**: The certificate type we are working with is `WIN_CERT_TYPE_PKCS_SIGNED_DATA`. Therefore, we set the value of *wCertificateType* to `0x2`.
 - **bCertificate**: This is the most important field. Although the security directory may contain multiple `bCertificate` entries, we will assume there is only one for our purposes. The bCertificate field is not a specific structure itself; in digital signatures, it contains another structure named `PKCS7`.

For the simplicity, we dump the security directory as a single file named `security_directory.bin` and will work on it.

# PKCS #n
There are multiple types of PKCS, each related to a specific function. Here is a list of PKCS types from [Wikipedia](https://en.wikipedia.org/wiki/PKCS):

- PKCS #1: RSA Cryptography Standard
- PKCS #2: *Withdrawn*
- PKCS #3: Diffie–Hellman Key Agreement Standard
- PKCS #4: *Withdrawn*
- PKCS #5: Password-based Encryption Standard
- PKCS #6: Extended-Certificate Syntax Standard
- **PKCS #7: Cryptographic Message Syntax Standard**
- PKCS #8: Private-Key Information Syntax Standard
- PKCS #9: Selected Attribute Types
- PKCS #10: Certification Request Standard
- PKCS #11: Cryptographic Token Interface
- PKCS #12: Personal Information Exchange Syntax Standard
- PKCS #13: Elliptic-curve cryptography Standard
- PKCS #14: Pseudo-random Number Generation
- PKCS #15: Cryptographic Token Information Format Standard

For digital signatures, the main focus is on PKCS #7, but we will also indirectly discuss PKCS #1, PKCS #9, and PKCS #13.

# Parsing PKCS #7

Let's return to our focus. The bCertificate field consists of a PKCS7 structure. First, we need to familiarize ourselves with its structure. Based on the [RFC](https://datatracker.ietf.org/doc/html/rfc2315#section-9.1), the signed data in PKCS7 format is defined as follows (in ASN.1 syntax):

```ASN.1
ContentInfo ::= SEQUENCE {
    contentType     ContentType,
    content         [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL 
}

ContentType ::= OBJECT IDENTIFIER
```   

> contentType indicates the type of content. It is an object identifier, which means it is a unique string of integers assigned by the authority that defines the content type. This document defines six content types: *data*, *signedData*, *envelopedData*, *signedAndEnvelopedData*, *digestedData*, and *encryptedData*.

Here we only consider the *signedData*, so the value of *content* field is as follows:

```ASN.1
SignedData ::= SEQUENCE {
    version             Version,
    digestAlgorithms    DigestAlgorithmIdentifiers,
    contentInfo         ContentInfo,
    certificates        [0] IMPLICIT   ExtendedCertificatesAndCertificates OPTIONAL,
    crls                [1] IMPLICIT   CertificateRevocationLists OPTIONAL,
    signerInfos         SignerInfos 
}
```

![Main ContentInfo File Offset](Images/MainContentInfo.jpg)

- The First 4 bytes are the `ContentInfo` field. It means it is a *SEQUENCE* contains 0x2369 bytes.
- The yellow box contains `contentType` field. It is an OID (Object Identifier) which defines the type of the content.
![SignedData OID](Images/signedDataOID.jpg)
- The unfinished green box contains `content` field. This field related to the value of *contentType*. Here, it is the signed data. The byte `0xA0` indicates *[0] EXPLICIT* contains 0x235A bytes. The next 4 bytes are the `SignedData` structure represented as a *SEQUENCE* and contains 0x2356 bytes.

*Note: For a brief introduction to `ASN.1`, refer to the appendix.*

By here, we parsed until offset 0x16. You can see numerous fields and their types. There are more details per field, but we will delve into some of the important fields required to continue. `contentInfo`, `certificates` and `signerInfos` are 3 important fields in the `SignedData` structure which we will discuss.

## version

It contains an *INTEGER* with size of 1 byte from offset 0x16 to offset 0x19. We discard this field.

## digestAlgorithms

```ASN.1
DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
```

It contains a *SET* with size of 0x0F bytes from offset 0x1A to offset 0x2A. We discard this field, too.

## contentInfo

```ASN.1
ContentInfo ::= SEQUENCE {
    contentType     ContentType,
    content         [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL 
}

ContentType ::= OBJECT IDENTIFIER

SpcIndirectDataContent ::= SEQUENCE {
    data                    SpcAttributeTypeAndOptionalValue,
    messageDigest           DigestInfo
}

SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
    type                    ObjectID,
    value                   [0] EXPLICIT ANY OPTIONAL
}

DigestInfo ::= SEQUENCE {
    digestAlgorithm     AlgorithmIdentifier,
    digest              OCTETSTRING
}

AlgorithmIdentifier    ::=    SEQUENCE {
    algorithm           ObjectID,
    parameters          [0] EXPLICIT ANY OPTIONAL
}
```

Warm-up is finished! `contentInfo` contains an *SEQUENCE* with size of 0x5C byte from offset 0x2B to offset 0x88.

![ContentInfo DigestAlgorithm File Offset](Images/ContentInfoOffset.JPG)

![ContentInfo ASN.1 Tree](Images/ContentInfoASNTree.jpg)

As you can see, `ContentInfo` field is a *SEQUENCE* containing two fields: `contentType` and `content`. In here, the `contentType` is an OID which defines the type of the content. The value of this field must be `1.3.6.1.4.1.311.2.1.4` which is `SpcIndirectDataContent`.

Now we know the type is `SpcIndirectDataContent`. It contains an important field named `DigestInfo` which itself contains `digestAlgorithm` and `digest`.

### digestAlgorithm
`digestAlgorithm` contains information about the algorithm (and its parameters) used to generate the digest.

![ContentInfo DigestAlgorithm File Offset](Images/digestAlgorithmFileOffset.jpg)

As you can see, it contains the hash algorithm used (`sha256`) and the parameters (`NULL`).

Here the list of most common hash algorithms with their OIDs and encoded DER representation:

```
MD2 		    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02}			// 1.2.840.113549.2.2
MD5 		    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05}			// 1.2.840.113549.2.5
SHA1 		    {0x2B, 0x0E, 0x03, 0x02, 0x1A}	 							// 1.3.14.3.2.26
SHA224 		    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04}		// 2.16.840.1.101.3.4.2.4
SHA256 		    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01} 		// 2.16.840.1.101.3.4.2.1
SHA384 		    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}		// 2.16.840.1.101.3.4.2.2
SHA512 		    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}		// 2.16.840.1.101.3.4.2.3
SHA512-224 	    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05}		// 2.16.840.1.101.3.4.2.5
SHA512-256 	    {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06}		// 2.16.840.1.101.3.4.2.6
```

*Note: It is worth noting that hte parameters are not always `NULL`.*

### digest

`digest` is the actual hash value of the PE image file. It's calculated using the hash algorithm specified in the `digestAlgorithm` field. Calculating the digest of a PE file is not a strait forward task! For moe information, refer to the appendix.

![ContentInfo Digest File Offset](Images/DigestFileOffset.jpg)

The bytes related to the `digest` field are highlighted in the image above. The first two bytes represent the ASN.1 tag and the length of the digest, followed by the actual digest value. In our sample file, the digest is: 
`5301B868A4D1743E3F4205078B85169A041CB9ABFF82D83372455D756025C748`

## certificates

This field is another important field of *SignedData* structure. This field encompasses all certificates involved in signing the PE file (usually excluding the topmost certificate in the certificate chain).  It is a sequence of certificates. Each certificate is represented as a sequence of ASN.1 encoded values.

According to [RFC](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1), the basic syntax for an X.509 v3 certificate is as follows:

```ASN.1
Certificate  ::=  SEQUENCE  {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING  
}

TBSCertificate  ::=  SEQUENCE  {
    version         [0]  EXPLICIT Version DEFAULT v1,
    serialNumber         CertificateSerialNumber,
    signature            AlgorithmIdentifier,
    issuer               Name,
    validity             Validity,
    subject              Name,
    subjectPublicKeyInfo SubjectPublicKeyInfo,
    issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                            -- If present, version MUST be v2 or v3
    subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                            -- If present, version MUST be v2 or v3
    extensions      [3]  EXPLICIT Extensions OPTIONAL
                            -- If present, version MUST be v3
}
```

Here, `certificates` contains two certificates with aggregated size of 0xD81 bytes from offset 0x89 to offset 0xE0A. It starts with byte *0xA0* indicates *[0] IMPLICIT*.

The first certificate with size 0x5FF starts from offset 0x8D and ends at offset 0x68F. The second certificate with size 0x77A starts from offset 0x690 and ends at offset 0xE0D. Please keep the start and end of offset the certificates in mind, because we need them to calculating the thumbprint in future subsection. For simplicity, we only parse the first certificate and ignore the second one. DO it as your practice!

The most important and the only field we delve into here is `TBSCertificate`. It contains a *SEQUENCE* of 10 fields: `version`, `serialNumber`, `signature`, `issuer`, `validity`, `subject`, `subjectPublicKeyInfo`, `issuerUniqueID`, `subjectUniqueID`, `extensions`.


### version

```
Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
```

It contains a *[0] EXPLICIT* tag of *INTEGER* with size of 1 bytes from offset 0x95 to offset 0x99. We discard this field. 

![Certificates Version File Offset](Images/CertificatesVersionFileOffset.jpg)

### serialNumber

```
CertificateSerialNumber  ::=  INTEGER
```

![Certificates Serial Number File Offset](Images/SerialNumberFileOffset.jpg)

One of the most important field of certificate is serial number. Ideally it is unique around the world. But precisely, it is almost unique. In world of X.509, it is supposed the CAs generates the serial number using `issuerDN + serial`. The term *"issuerDN"* typically refers to the distinguished name (DN) of the issuer in a digital certificate. The issuer DN contains information about the entity that issued the certificate. The *"serial"* is an internal ID of the CAs that uniques certificates issued by them. But in real that does not happen.

This contains a *INTEGER* with size of 0x13 bytes from offset 0x9A to offset 0xAE. In next sections, We use the serial number to determine which certificate got involved in signing the PE file.

Here, the serial number of the first certificate is: 
`33 00 00 01 87 72 17 72 15 59 40 C7 09 00 00 00 00 01 87`

### signature

```
AlgorithmIdentifier  ::=  SEQUENCE  {
    algorithm               OBJECT IDENTIFIER,
    parameters              ANY DEFINED BY algorithm OPTIONAL  
}
```

It contains a *SEQUENCE* with size of 0xD bytes from offset 0xAF to offset 0xBD. We discard this field. 

![Certificates Signature File Offset](Images/CertificatesSignatureFileOffset.jpg)

### issuer

It contains a *SEQUENCE* with size of 0x7E bytes from offset 0xBE to offset 0x13D. We discard this field. 

![Certificates Issuer File Offset](Images/CertificatesIssuerFileOffset.jpg)

### validity

It contains a *SEQUENCE* with size of 0x1E bytes from offset 0x13E to offset 0x15D. We discard this field. 

![Certificates Validity File Offset](Images/CertificatesValidityFileOffset.jpg)

### subject

It contains a *SEQUENCE* with size of 0x74 bytes from offset 0x15E to offset 0x1D3. We discard this field. 

![Certificates Subject File Offset](Images/CertificatesSubjectFileOffset.jpg)





### subjectPublicKeyInfo

```
SubjectPublicKeyInfo  ::=  SEQUENCE  {
    algorithm            AlgorithmIdentifier,
    subjectPublicKey     BIT STRING  
}
```

![Certificates Subject Public Key Info File Offset](Images/CertificatessubjectPublicKeyInfoFileOffset.jpg)


![Certificates Subject Public Key Info ASN Tree](Images/CertificatessubjectPublicKeyInfoASNTree.jpg)



### issuerUniqueID

```
UniqueIdentifier  ::=  BIT STRING
```

This field starts with byte *0xA1* indicates *[1] IMPLICIT*. The byte at offset 0x2fA is *0xA3*. So. this field does not exist for this certificate.

### subjectUniqueID

```
UniqueIdentifier  ::=  BIT STRING
```

This field starts with byte *0xA2* indicates *[2] IMPLICIT*. The bytes at offset 0x2fA is *0xA3*. So. this field does not exist for this certificate.

### extensions

This field starts with byte *0xA3* indicates *[3] EXPLICIT*. The bytes at offset 0x2fA is *0xA3*. So. this field exists for this certificate.

It contains a *SEQUENCE* with size of 0x17A bytes from offset 0x2fE to offset 0x47B. We discard this field. 

![Certificates Extensions File Offset](Images/CertificatesExtensionsFileOffset.jpg)


## signatureAlgorithm

It contains a *SEQUENCE* with size of 0xD bytes from offset 0x47C to offset 0x48A. As mentioned, we decided to discuss only about the `TBSCertificate` field. So, we discard this field. 

![Certificates SignatureAlgorithm File Offset](Images/CertificatesSignatureAlgorithmFileOffset.jpg)

## signatureValue

It contains a *BIT STRING* with size of 0x201 bytes from offset 0x48B to offset 0x68F. We discard this field. As mentioned, we decided to discuss only about the `TBSCertificate` field. So, we discard this field. 

![Certificates SignatureValue File Offset](Images/CertificatesSignatureValueFileOffset.jpg)

### Calculating thumbprint

## crls

## signerInfos

```
SignerInfos ::= SET OF SignerInfo

SignerInfo ::= SEQUENCE {
    version                     Version,
    issuerAndSerialNumber       IssuerAndSerialNumber,
    digestAlgorithm             DigestAlgorithmIdentifier,
    authenticatedAttributes     [0] IMPLICIT Attributes OPTIONAL,
    digestEncryptionAlgorithm   DigestEncryptionAlgorithmIdentifier,
    encryptedDigest             EncryptedDigest,
    unauthenticatedAttributes   [1] IMPLICIT Attributes OPTIONAL 
}
```    

### Parsing issuerAndSerialNumber

### Parsing digestAlgorithm

### Parsing authenticatedAttributes

### Parsing digestEncryptionAlgorithm

### Parsing encryptedDigest

# Appendix A: PE Authenticode Hash 

# Appendix B: A Brief Introduction to ASN.1

# Appendix C: Most Important Fields

