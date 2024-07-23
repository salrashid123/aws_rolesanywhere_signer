// Provides an AWS Credential based on AWS RolesAnywhere certificate and keys
//
// Currently, the only way to use a roles anywhere credential in an aws SDK is to use
// a process credential provided by https://github.com/aws/rolesanywhere-credential-helper
//
// This library on the other hand, performs the same exchange provided by the process credential but
// this one allows you to provide *any* golang crypto.Signer which hosts the private key.
//
// Possible crypto.Signers can save the private key to HSM, Trusted Platform Module,
// PKCS11 or simply RSA/ECC private keys.
// Note, a large chunk of this is from https://github.com/aws/rolesanywhere-credential-helper

package rolesanywhere

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"runtime"

	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv1 "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/rolesanywhere-credential-helper/rolesanywhere"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
)

const (
	ProviderName     = "RolesAnywhereSignerProvider"
	refreshTolerance = 60
	defaultVersion   = "2011-06-15"
)

type CertIdentifier struct {
	Subject         string
	Issuer          string
	SerialNumber    *big.Int
	SystemStoreName string // Only relevant in the case of Windows
}

type CredentialsOpts struct {
	Certificate      *x509.Certificate // x509 certificate associated with the private key and issued by the CA
	CertificateChain []*x509.Certificate

	CertIdentifier    CertIdentifier
	RoleArn           string // RoleARN (eg. arn:aws:iam::291738886548:role/rolesanywhere1)
	ProfileArnStr     string // ProfileARN (eg arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380)
	TrustAnchorArnStr string // TrustAnchorARN (eg arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92da)
	SessionDuration   int
	Region            string // Region (eg us-east-2)
	Endpoint          string
	NoVerifySSL       bool
	WithProxy         bool
	Version           string
	Date              time.Time // set the date/time for the credential generation (you shouldn't have to ever set this)

	Debug bool
}

type signerParams struct {
	OverriddenDate   time.Time
	RegionName       string
	ServiceName      string
	SigningAlgorithm string
}

// Configures the Credential source where the private key is represented by a crypto.Signer
//
// You must specify the Singer as well as the CredentialsOpts which contains the minimum
// RolesAnywhere settings:
// Certificate, RoleArn, ProfileArnStr, TrustAnchorArnStr, Region
func NewAWSRolesAnywhereSignerCredentials(cfg SignerProvider) (*signerCredentialsProvider, error) {

	if cfg.Certificate == nil || cfg.Region == "" || cfg.TrustAnchorArnStr == "" || cfg.RoleArn == "" || cfg.ProfileArnStr == "" || cfg.Signer == nil {
		return &signerCredentialsProvider{}, errors.New("error Certificate, Region, TrustAnchorArnStr, RoleArn, ProfileArnStr, Signer must all be set")
	}

	if cfg.CredentialsOpts.SessionDuration == 0 {
		cfg.CredentialsOpts.SessionDuration = 3600
	}
	return &signerCredentialsProvider{
		signer:          cfg.Signer,
		CredentialsOpts: cfg.CredentialsOpts,
	}, nil
}

func (s *signerCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {

	// Assign values to region and endpoint if they haven't already been assigned
	trustAnchorArn, err := arn.Parse(s.CredentialsOpts.TrustAnchorArnStr)
	if err != nil {
		return aws.Credentials{}, err
	}
	profileArn, err := arn.Parse(s.CredentialsOpts.ProfileArnStr)
	if err != nil {
		return aws.Credentials{}, err
	}

	if trustAnchorArn.Region != profileArn.Region {
		return aws.Credentials{}, errors.New("trust anchor and profile regions don't match")
	}

	if s.CredentialsOpts.Region == "" {
		s.CredentialsOpts.Region = trustAnchorArn.Region
	}

	mySession := session.Must(session.NewSession())

	var tr *http.Transport
	if s.CredentialsOpts.WithProxy {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: s.CredentialsOpts.NoVerifySSL},
			Proxy:           http.ProxyFromEnvironment,
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: s.CredentialsOpts.NoVerifySSL},
		}
	}

	debugLevel := awsv1.LogOff
	if s.CredentialsOpts.Debug {
		debugLevel = awsv1.LogDebug
	}
	client := &http.Client{Transport: tr}
	config := awsv1.NewConfig().WithRegion(s.CredentialsOpts.Region).WithHTTPClient(client).WithLogLevel(debugLevel)
	if s.CredentialsOpts.Endpoint != "" {
		config.WithEndpoint(s.CredentialsOpts.Endpoint)
	}
	rolesAnywhereClient := rolesanywhere.New(mySession, config)
	rolesAnywhereClient.Handlers.Build.RemoveByName("core.SDKVersionUserAgentHandler")
	rolesAnywhereClient.Handlers.Build.PushBackNamed(request.NamedHandler{Name: "v4x509.CredHelperUserAgentHandler", Fn: request.MakeAddToUserAgentHandler("CredSigner", "1", runtime.Version(), runtime.GOOS, runtime.GOARCH)})
	rolesAnywhereClient.Handlers.Sign.Clear()
	certificate := s.CredentialsOpts.Certificate
	certificateChain := s.CredentialsOpts.CertificateChain

	var signatureAlgorithm string
	k := s.signer.Public()
	switch k.(type) {
	case *ecdsa.PublicKey:
		signatureAlgorithm = aws4_x509_ecdsa_sha256
	case *rsa.PublicKey:
		signatureAlgorithm = aws4_x509_rsa_sha256
	default:
		return aws.Credentials{}, errors.New("unsupported signature algorithm")
	}

	rolesAnywhereClient.Handlers.Sign.PushBackNamed(request.NamedHandler{Name: "v4x509.SignRequestHandler", Fn: createRequestSignFunction(s.signer, signatureAlgorithm, certificate, certificateChain, s.Date)})

	certificateStr := base64.StdEncoding.EncodeToString(certificate.Raw)
	durationSeconds := int64(s.CredentialsOpts.SessionDuration)
	createSessionRequest := rolesanywhere.CreateSessionInput{
		Cert:               &certificateStr,
		ProfileArn:         &s.CredentialsOpts.ProfileArnStr,
		TrustAnchorArn:     &s.CredentialsOpts.TrustAnchorArnStr,
		DurationSeconds:    aws.Int64(durationSeconds),
		InstanceProperties: nil,
		RoleArn:            &s.CredentialsOpts.RoleArn,
		SessionName:        nil,
	}
	output, err := rolesAnywhereClient.CreateSession(&createSessionRequest)
	if err != nil {
		return aws.Credentials{}, err
	}

	if len(output.CredentialSet) == 0 {
		return aws.Credentials{}, errors.New("unable to obtain temporary security credentials from CreateSession")
	}
	credentials := output.CredentialSet[0].Credentials

	t, err := time.Parse(time.RFC3339, *credentials.Expiration)
	if err != nil {
		return aws.Credentials{}, err
	}
	s.expiration = t
	return aws.Credentials{
		AccessKeyID:     *credentials.AccessKeyId,
		SecretAccessKey: *credentials.SecretAccessKey,
		SessionToken:    *credentials.SessionToken,
		Expires:         t,
		Source:          ProviderName,
		CanExpire:       true,
	}, nil

}

func (s *signerCredentialsProvider) IsExpired() bool {
	return time.Now().Add(time.Second * time.Duration(refreshTolerance)).After(s.expiration)
}

func (s *signerCredentialsProvider) ExpiresAt() time.Time {
	return s.expiration
}
