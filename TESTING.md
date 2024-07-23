## Testing

The test cases in `credentials_test.go` simply checks for if the caller created a specific signature from an RSA based keys.

It basically uses the same rsa key and a known date/time `20240706T113859Z` as shown below and then verifies if the Authorization header it generated matches what you would see with the cli:

The main problem is that it only tests RSA keys (since ECC signatures are not deterministic) and in general this is more or less a 'fake' test.

An improvement TODO for testing could be to actually verify the signature using the header values during the test.  For example, implment a variation the code in `example/protocol/main.go` where the inbound headers are used to recreate the string to sign and then use that to verify the signature and parameters provided by the client.

### RSA

```bash
export REGION=us-east-2
export CERT_PATH=certs/alice-cert.crt
export ROLE_ARN=arn:aws:iam::291738886548:role/rolesanywhere1
export TRUST_ANCHOR_ARN=arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92da
export PROFILE_ARN=arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380


$ ./aws_signing_helper credential-process     --certificate $CERT_PATH     --private-key certs/alice-cert.key     --role-arn $ROLE_ARN     --trust-anchor-arn $TRUST_ANCHOR_ARN     --profile-arn $PROFILE_ARN --endpoint http://127.0.0.1:8080 --debug

2024/07/06 07:38:59 attempting to use FileSystemSigner
2024/07/06 07:38:59 DEBUG: Request Roles Anywhere/CreateSession Details:
---[ REQUEST POST-SIGN ]-----------------------------
POST /sessions?profileArn=arn%3Aaws%3Arolesanywhere%3Aus-east-2%3A291738886548%3Aprofile%2F6f4943fb-13d4-4242-89c4-be367595c380&roleArn=arn%3Aaws%3Aiam%3A%3A291738886548%3Arole%2Frolesanywhere1&trustAnchorArn=arn%3Aaws%3Arolesanywhere%3Aus-east-2%3A291738886548%3Atrust-anchor%2Fa545a1fc-5d86-4032-8f4c-61cdd6ff92da HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: CredHelper/1.1.1 (go1.22.4; linux; amd64)
Transfer-Encoding: chunked
Authorization: AWS4-X509-RSA-SHA256 Credential=21/20240706/us-east-2/rolesanywhere/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-x509, Signature=500d79d98f50408908db67bd9b794cef9233768063c301d520a792cfc1e84644386a908e67e88003cc98478ae3fec8cd8fd7c42a137b7d338d8d58f250f58a78faa0530a5e90a16be0a98b53162e4dd4b124a753fdcd007f106f82346f424024399fe8af0cb95dbf0601ce37c12747c35f8c1f2ac03289982de9fecfb15a0186575ba2040329ccedc7526b339367b39b76a1b9b834622af0fd7cc11c5fe458ce62da3a7b4fbede02a921134498c50992267249a28d3defd2cb31a7927cdbba56e02f3ce027aadcd60449b6274e3daef6766163a2eb848e4339e7f9ca88b36c83edd6ef28952b10dec2a97eee7780a07d15f8a4b707211c3445b0b367dffff45d
Content-Type: application/json
X-Amz-Date: 20240706T113859Z
X-Amz-X509: MIIENTCCAx2gAwIBAgIBFTANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnByaXNlMRcwFQYDVQQDDA5TaW5nbGUgUm9vdCBDQTAeFw0yNDA1MTgxNDQ5MzFaFw0zNDA1MTgxNDQ5MzFaMFMxCzAJBgNVBAcMAlVTMQ8wDQYDVQQKDAZHb29nbGUxEzARBgNVBAsMCkVudGVycHJpc2UxHjAcBgNVBAMMFWFsaWNlLWNlcnQuZG9tYWluLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOwmW5PGCbkRYKrWjyFstW6KUjC2g6EMWOdhrnUiDYrJ2tyY0DIgowUX9MFdBvfXBQmB4BMm1750U0/g4TV5brxyByNhQWljGBb0J40cMzFZYWzBdvAs5Xzp1NCTKwcndxAvq8EBeBwnaOcouu9khP5iL9TxqMqD3ydRUKO4UXgLBL7VtUOhTIn6eCLWRVDyShooAKVqFYQbRlHeLTxlwouckx1T2k80NB+109SngaorRIC0/1hRLOfL1FMYraNJgZtRxUpd8Kd99+vMAIkTnzaej00jfvI23cvM47Z7sblNhxKKMy2WjMEKbpijVCmYhnmXM0JtyuFhe7wgDTBUkj8CAwEAAaOCARkwggEVMA4GA1UdDwEB/wQEAwIHgDAJBgNVHRMEAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBTW9zsS63ojE7V+aUGi5iy4VCcdWDAfBgNVHSMEGDAWgBTs8OpTUz+fI9zBDjEQNwfe3udu8zBFBggrBgEFBQcBAQQ5MDcwNQYIKwYBBQUHMAKGKWh0dHA6Ly9wa2kuZXNvZGVtb2FwcDIuY29tL2NhL3Jvb3QtY2EuY2VyMDoGA1UdHwQzMDEwL6AtoCuGKWh0dHA6Ly9wa2kuZXNvZGVtb2FwcDIuY29tL2NhL3Jvb3QtY2EuY3JsMCAGA1UdEQQZMBeCFWFsaWNlLWNlcnQuZG9tYWluLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAgPktGR1U2f8mT6PLYtYutejj0su5qxOeOV5EcARm3H2mVS3+GyKxyaADaFJdwuwPPTO/64Do2HxwImXC59CNKbOwyOLi10QeJD9AqsHSvCqwTsT7oWpMO64ngBGa9QuUh/C1UGKKqj8Sqsnf/IsfNQ28Y0x0dQUiue/005Ef2+8gqt22gyNwwfvFSPscrXGCA10V8wvq8jp8k2GZTQr8w0EhP0Hpnts9IXuhGO4HCIZA2MGwdZqliEFhwgQlDzD145OFe1CJTRm7fbbSHDROZwMKPc31mDuCn4PcDtcM+VF5lAH35DghJaX92xyYm+ECPhMBAVqkA8e1WaZdGKi03Q==
Accept-Encoding: gzip
```


### ECC


```bash
export REGION=us-east-2
export CERT_PATH=certs/alice-cert-ecc.crt
export ROLE_ARN=arn:aws:iam::291738886548:role/rolesanywhere1
export TRUST_ANCHOR_ARN=arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/1cb4e36e-e4ad-4bbb-9b37-fdafb2cbe4fe
export PROFILE_ARN=arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380


$ ./aws_signing_helper credential-process     --certificate $CERT_PATH     --private-key certs/alice-cert-ecc.key     --role-arn $ROLE_ARN     --trust-anchor-arn $TRUST_ANCHOR_ARN     --profile-arn $PROFILE_ARN  --endpoint http://127.0.0.1:8080 --debug

2024/07/06 10:30:04 attempting to use FileSystemSigner
2024/07/06 10:30:04 DEBUG: Request Roles Anywhere/CreateSession Details:
---[ REQUEST POST-SIGN ]-----------------------------
POST /sessions?profileArn=arn%3Aaws%3Arolesanywhere%3Aus-east-2%3A291738886548%3Aprofile%2F6f4943fb-13d4-4242-89c4-be367595c380&roleArn=arn%3Aaws%3Aiam%3A%3A291738886548%3Arole%2Frolesanywhere1&trustAnchorArn=arn%3Aaws%3Arolesanywhere%3Aus-east-2%3A291738886548%3Atrust-anchor%2F1cb4e36e-e4ad-4bbb-9b37-fdafb2cbe4fe HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: CredHelper/1.1.1 (go1.22.4; linux; amd64)
Transfer-Encoding: chunked
Authorization: AWS4-X509-ECDSA-SHA256 Credential=3/20240706/us-east-2/rolesanywhere/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-x509, Signature=3065023100cacc4b06cc8de2a5a11daf3e0a03423da6b7ad17dc4f54cbafe0102824f36c65ed6c04554e5864f31eea0f4b0d2c496d02302f600f65512e17a454a9b10b5b0aaf2882a37cc4bab3e14c0ee3c627b5f02bbe457126471c186712e4650e2bbe6db273
Content-Type: application/json
X-Amz-Date: 20240706T143004Z
X-Amz-X509: MIICxjCCAkygAwIBAgIBAzAKBggqhkjOPQQDAjBQMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnByaXNlMRswGQYDVQQDDBJFbnRlcnByaXNlIFJvb3QgQ0EwHhcNMjQwNzA2MTM1NDM4WhcNMzQwNzA2MTM1NDM4WjBTMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMRMwEQYDVQQLDApFbnRlcnByaXNlMR4wHAYDVQQDDBVhbGljZS1jZXJ0LmRvbWFpbi5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQyphA+fjw2izjBi/1DbhmdU7GdlwH8kAsnmsnz6ZAEI1SmGHPq+p+GU5B6kxxEUV9HIK9NKrUHmgq57nMK8hURUNgvZO1g4lm3NCOmwxiWdhpUVwebj9EIkXo5hGjAq0yjgfYwgfMwDgYDVR0PAQH/BAQDAgeAMAkGA1UdEwQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFIgAM2YwMfgPo08j4fO4HSjxtLkDMB8GA1UdIwQYMBaAFDbwo13LgAyeM5VcrAzwf+Bvt4C5MEUGCCsGAQUFBwEBBDkwNzA1BggrBgEFBQcwAoYpaHR0cDovL3BraS5lc29kZW1vYXBwMi5jb20vY2Evcm9vdC1jYS5jZXIwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL3BraS5lc29kZW1vYXBwMi5jb20vY2Evcm9vdC1jYS5jcmwwCgYIKoZIzj0EAwIDaAAwZQIwZt7SNQq5I5NaWRSetokyWveXDoJXP+Qy51aUtR92NGBTFDMdJ+Kav5Ak+A9JaukwAjEAz/f5gpyVDsHFOpIgA+ebloEoUHOJgYQTB/BBMksRg5aPssVHvSEWcXymhXH0NBh6
Accept-Encoding: gzip
```