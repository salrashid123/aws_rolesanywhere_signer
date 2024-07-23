package rolesanywhere

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	//"github.com/stretchr/testify/assert"
)

func TestMockCredentialEndToEnd(t *testing.T) {

	roleARN := "arn:aws:iam::291738886548:role/rolesanywhere1"
	profileARN := "arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380"

	rsaCert := "./example/certs/alice-cert.crt"
	rsaKey := "./example/certs/alice-cert.key"
	rsaTrustAnchor := "arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92da"
	rsaSignedHeader := "AWS4-X509-RSA-SHA256 Credential=21/20240706/us-east-2/rolesanywhere/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-x509, Signature=500d79d98f50408908db67bd9b794cef9233768063c301d520a792cfc1e84644386a908e67e88003cc98478ae3fec8cd8fd7c42a137b7d338d8d58f250f58a78faa0530a5e90a16be0a98b53162e4dd4b124a753fdcd007f106f82346f424024399fe8af0cb95dbf0601ce37c12747c35f8c1f2ac03289982de9fecfb15a0186575ba2040329ccedc7526b339367b39b76a1b9b834622af0fd7cc11c5fe458ce62da3a7b4fbede02a921134498c50992267249a28d3defd2cb31a7927cdbba56e02f3ce027aadcd60449b6274e3daef6766163a2eb848e4339e7f9ca88b36c83edd6ef28952b10dec2a97eee7780a07d15f8a4b707211c3445b0b367dffff45d"

	tests := []struct {
		name              string
		region            string
		certificate       string
		bundlePath        string
		privatekey        string
		rolearn           string
		trustanchorarn    string
		profilearn        string
		date              string
		response          string
		callShouldSucceed bool
	}{
		{"get-credentials-rsa-success", "us-east-2", rsaCert, "", rsaKey, roleARN, rsaTrustAnchor, profileARN, "20240706T113859Z", rsaSignedHeader, true},
		{"get-credentials-rsa-fail-signature", "us-east-2", rsaCert, "", rsaKey, roleARN, rsaTrustAnchor, profileARN, "20240706T113859Z", "invalidsignature", false},
		{"get-credentials-rsa-fail-invalid-profile", "us-east-2", rsaCert, "", rsaKey, roleARN, rsaTrustAnchor, "invalid_profile", "20240706T113859Z", rsaSignedHeader, false},
		{"get-credentials-rsa-fail-invalid-anchor", "us-east-2", rsaCert, "", rsaKey, roleARN, "invalid_anchor", profileARN, "20240706T113859Z", rsaSignedHeader, false},
		{"get-credentials-rsa-fail-invalid-role", "us-east-2", rsaCert, "", rsaKey, "invalid-role", rsaTrustAnchor, profileARN, "20240706T113859Z", rsaSignedHeader, false},
		{"get-credentials-rsa-fail-invalid-key", "us-east-2", rsaCert, "", "./example/certs/alice-cert-ecc.key", roleARN, rsaTrustAnchor, profileARN, "20240706T113859Z", rsaSignedHeader, false},
		{"get-credentials-rsa-fail-invalid-cert", "us-east-2", "./example/certs/alice-cert-ecc.crt", "", rsaKey, roleARN, rsaTrustAnchor, profileARN, "20240706T113859Z", rsaSignedHeader, false},
		{"get-credentials-rsa-fail-bad-date", "us-east-2", rsaCert, "", rsaKey, roleARN, rsaTrustAnchor, profileARN, "20240806T113859Z", rsaSignedHeader, false},
		{"get-credentials-rsa-fail-bad-zone", "us-east-1", rsaCert, "", rsaKey, roleARN, rsaTrustAnchor, profileARN, "20240806T113859Z", rsaSignedHeader, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			// create a listener with the desired port.
			l, err := net.Listen("tcp", "127.0.0.1:8080")
			if err != nil {
				t.Logf("Error starting test server listener %v", err)
				t.Fail()
			}

			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				c, err := os.ReadFile(tc.certificate)
				if err != nil {
					t.Logf("Error reading certificate file %v", err)
					t.Fail()
				}

				block, _ := pem.Decode(c)

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Logf("Error parsing certificate %v", err)
					t.Fail()
				}

				amz_x509 := base64.StdEncoding.EncodeToString(cert.Raw)

				au := r.Header.Get("Authorization")
				dt := r.Header.Get("X-Amz-Date")
				crh := r.Header.Get("X-Amz-X509")
				if au != tc.response || dt != tc.date || crh != amz_x509 {
					// if tc.callShouldSucceed {
					// 	t.Logf("Expected X-Amz-Date [%s], got [%s]\n", tc.date, dt)
					// 	t.Logf("Expected X-Amz-X509 [%s], got [%s]\n", amz_x509, crh)
					// 	t.Logf("Expected Authorization [%s], got [%s]\n", tc.response, au)
					// }
					w.WriteHeader(http.StatusUnauthorized)
					w.Header().Set("Content-Type", "application/json")
					return
				}
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte(`{
			"credentialSet":[
			  {
				"assumedRoleUser": {
				"arn": "arn:aws:sts::000000000000:assumed-role/ExampleS3WriteRole",
				"assumedRoleId": "assumedRoleId"
				},
				"credentials":{
				  "accessKeyId": "accessKeyId",
				  "expiration": "2022-07-27T04:36:55Z",
				  "secretAccessKey": "secretAccessKey",
				  "sessionToken": "sessionToken"
				},
				"packedPolicySize": 10,
				"roleArn": "arn:aws:iam::000000000000:role/ExampleS3WriteRole",
				"sourceIdentity": "sourceIdentity"
			  }
			],
			"subjectArn": "arn:aws:rolesanywhere:us-east-1:000000000000:subject/41cl0bae-6783-40d4-ab20-65dc5d922e45"
		  }`))
			}))

			ts.Listener.Close()
			ts.Listener = l
			ts.Start()
			defer ts.Close()

			privateKey := tc.privatekey
			bundlePath := ""
			certPath := tc.certificate
			var chain []*x509.Certificate
			if bundlePath != "" {
				var err error
				chain, err = helper.GetCertChain(bundlePath)
				if err != nil {
					t.Logf("Could not initialize TPM Credentials error reading bundle %v\n", err)
					t.Fail()
				}
			}
			var cert *x509.Certificate
			if certPath != "" {
				var err error
				_, cert, err = helper.ReadCertificateData(certPath)
				if err != nil {
					t.Logf("Could not initialize TPM Credentials; error reading certificate %v\n", err)
					t.Fail()
				}
			} else if len(chain) > 0 {
				cert = chain[0]
			} else {
				t.Logf("Could not initialize credentials: no valid certificates provided \n")
				t.Fail()
			}

			b, err := os.ReadFile(privateKey)
			if err != nil {
				t.Logf("Could not read private key %v\n", err)
				t.Fail()
			}
			block, _ := pem.Decode(b)
			parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Logf("Could not initialize TPM Credentials; error reading private key %v\n", err)
				t.Fail()
			}

			var key crypto.Signer

			switch parseResult.(type) {
			case *rsa.PrivateKey:
				key = parseResult.(*rsa.PrivateKey)
			case *ecdsa.PrivateKey:
				key = parseResult.(*ecdsa.PrivateKey)

			default:
				t.Logf("unsupported keytype %v\n", err)
				t.Fail()
			}

			dt, err := time.Parse(timeFormat, tc.date)
			if err != nil {
				t.Logf("Could not initialize datetime  %v\n", err)
				t.Fail()
			}

			sessionCredentials, err := NewAWSRolesAnywhereSignerCredentials(SignerProvider{
				CredentialsOpts: CredentialsOpts{
					Region:            tc.region,
					ProfileArnStr:     tc.profilearn,
					TrustAnchorArnStr: tc.trustanchorarn,
					RoleArn:           tc.rolearn,
					Certificate:       cert,
					CertificateChain:  chain,
					Debug:             false,
					Date:              dt,

					Endpoint: ts.URL,
				},
				Signer: key,
			})
			if err != nil {
				t.Logf("Could not initialize TPM Credentials %v\n", err)
				t.Fail()
			}

			cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-east-2"), config.WithCredentialsProvider(sessionCredentials))
			if err != nil {
				t.Logf("Could not read GetCallerIdentity response %v", err)
				t.Fail()
			}

			// if you want to output the same thing a process credential does:
			_, err = cfg.Credentials.Retrieve(context.Background())
			if tc.callShouldSucceed && err != nil {
				t.Logf("Error getting credentials; expected success; got error  %v", err)
				t.Fail()
			}
		})

	}
}
