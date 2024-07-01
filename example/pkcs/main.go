package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"

	"flag"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/ThalesIgnite/crypto11"
	salpkcs "github.com/salrashid123/mtls_pkcs11/signer/pkcs"

	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	rolesanywhere "github.com/salrashid123/aws_rolesanywhere_signer"
)

const ()

var (
	bundlePath     = flag.String("bundlePath", "", "x509 certificate bundle")
	certPath       = flag.String("certPath", "certs/alice-cert.crt", "x509 certificate")
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

	pkconfig := &crypto11.Config{
		Path:       "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		TokenLabel: "token1",
		Pin:        "mynewpin",
	}
	cctx, err := crypto11.Configure(pkconfig)
	if err != nil {
		log.Fatal(err)
	}
	//defer cctx.Close()

	key, err := salpkcs.NewPKCSCrypto(&salpkcs.PKCS{
		Context:        cctx,
		PkcsId:         nil,
		PkcsLabel:      []byte("keylabel1"),
		PublicCertFile: "certs/alice-cert.crt",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer key.Context.Close()

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

	// *******************************************

	fmt.Println("-------------------------------- GetCallerIdentity with SessionToken SDK")

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(*awsRegion), config.WithCredentialsProvider(sessionCredentials))
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v", err)
		return
	}

	stssvc := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Region = *awsRegion
	})

	ctx := context.Background()
	stsresp, err := stssvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v\n", err)
		return
	}
	fmt.Printf("STS Identity from API %s\n", *stsresp.UserId)

	// s3Client := s3.NewFromConfig(cfg)

	// output, err := s3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	// if err != nil {
	//  panic(err.Error())
	// }

	// for index, bucket := range output.Buckets {
	//  fmt.Printf("Bucket %v: %v\n", index+1, *bucket.Name)
	// }

}
