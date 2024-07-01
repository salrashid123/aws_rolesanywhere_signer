package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"

	"flag"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/go-piv/piv-go/piv"
	rolesanywhere "github.com/salrashid123/aws_rolesanywhere_signer"
)

const ()

var (
	bundlePath     = flag.String("bundlePath", "", "x509 certificate bundle")
	certPath       = flag.String("certPath", "certs/alice-cert.crt", "x509 certificate")
	ykPIN          = flag.String("pin", "123456", "PIN for the yubikey")
	awsRegion      = flag.String("awsRegion", "us-east-2", "AWS Region")
	roleARN        = flag.String("roleARN", "arn:aws:iam::291738886548:role/rolesanywhere1", "Role to assume")
	trustAnchorARN = flag.String("trustAnchorARN", "arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92da", "Trust Anchor ARN")
	profileARN     = flag.String("profileARN", "arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380", "Profile ARN")
)

func main() {
	flag.Parse()

	// ***************************************************************************

	var chain []*x509.Certificate
	if *bundlePath != "" {
		var err error
		chain, err = helper.GetCertChain(*bundlePath)
		if err != nil {
			log.Printf("Failed to read certificate bundle: %s\n", err)
			return
		}
	}
	var cert *x509.Certificate
	if *certPath != "" {
		var err error
		_, cert, err = helper.ReadCertificateData(*certPath)
		if err != nil {
			log.Printf("error reading certificate %v", err)
			return
		}
	} else if len(chain) > 0 {
		cert = chain[0]
	} else {
		log.Println("No certificate path or certificate bundle path provided")
		return
	}

	cards, err := piv.Cards()
	if err != nil {
		fmt.Printf("Could not initialize yubikey cards %v\n", err)
		return
	}
	var ykey *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			if ykey, err = piv.Open(card); err != nil {
				fmt.Printf("unable to open yubikey %v", err)
				os.Exit(1)
			}
			break
		}
	}
	if ykey == nil {
		fmt.Printf("Could not initialize yubikey Credentials %v\n", err)
		return
	}
	defer ykey.Close()

	cc, err := ykey.Certificate(piv.SlotSignature)
	if err != nil {
		fmt.Printf("Could not initialize certificate Credentials %v\n", err)
		return
	}
	auth := piv.KeyAuth{PIN: piv.DefaultPIN}
	priv, err := ykey.PrivateKey(piv.SlotSignature, cc.PublicKey, auth)
	if err != nil {
		fmt.Printf("Could not initialize private key Credentials %v\n", err)
		return
	}
	key, ok := priv.(crypto.Signer)
	if !ok {
		fmt.Printf("Could not initialize yubikey signer %v\n", err)
		return
	}
	sessionCredentials, err := rolesanywhere.NewAWSRolesAnywhereSignerCredentials(rolesanywhere.SignerProvider{
		CredentialsOpts: rolesanywhere.CredentialsOpts{
			Region:            *awsRegion,
			RoleArn:           *roleARN,
			TrustAnchorArnStr: *trustAnchorARN,
			ProfileArnStr:     *profileARN,
			Certificate:       cert,
			CertificateChain:  chain,
			Debug:             false,
		},
		Signer: key,
	})
	if err != nil {
		fmt.Printf("Could not initialize TPM Credentials %v\n", err)
		return
	}

	ctx := context.Background()

	// *******************************************

	fmt.Println("-------------------------------- GetCallerIdentity with SessionToken SDK")

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(*awsRegion), config.WithCredentialsProvider(sessionCredentials))
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v", err)
		return
	}

	// if you want to output the same thing a process credential does:
	// c, err := cfg.Credentials.Retrieve(context.Background())
	// if err != nil {
	// 	fmt.Printf("Could not read credentials %v", err)
	// 	return
	// }

	// type CredentialProcessOutput struct {
	// 	// This field should be hard-coded to 1 for now.
	// 	Version int `json:"Version"`
	// 	// AWS Access Key ID
	// 	AccessKeyId string `json:"AccessKeyId"`
	// 	// AWS Secret Access Key
	// 	SecretAccessKey string `json:"SecretAccessKey"`
	// 	// AWS Session Token for temporary credentials
	// 	SessionToken string `json:"SessionToken"`
	// 	// ISO8601 timestamp for when the credentials expire
	// 	Expiration string `json:"Expiration"`
	// }

	// credentialProcessOutput := CredentialProcessOutput{
	// 	Version:         1,
	// 	AccessKeyId:     c.AccessKeyID,
	// 	SecretAccessKey: c.SecretAccessKey,
	// 	SessionToken:    c.SessionToken,
	// 	Expiration:      c.Expires.Format(time.RFC3339),
	// }
	// bb, err := json.MarshalIndent(credentialProcessOutput, "", "  ")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Print(string(bb))

	stssvc := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Region = *awsRegion
	})

	stsresp, err := stssvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v\n", err)
		return
	}
	fmt.Printf("STS Identity from API %s\n", *stsresp.UserId)

	// s3Client := s3.NewFromConfig(cfg)

	// output, err := s3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	// if err != nil {
	// 	panic(err.Error())
	// }

	// for index, bucket := range output.Buckets {
	// 	fmt.Printf("Bucket %v: %v\n", index+1, *bucket.Name)
	// }

}
