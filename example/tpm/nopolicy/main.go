package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"flag"

	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/aws/aws-sdk-go-v2/config"
	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	rolesanywhere "github.com/salrashid123/aws_rolesanywhere_signer"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	saltpm "github.com/salrashid123/signer/tpm"
)

const ()

var (
	bundlePath = flag.String("bundlePath", "", "x509 certificate bundle")
	certPath   = flag.String("certPath", "certs/alice-cert.crt", "x509 certificate")

	awsRegion      = flag.String("awsRegion", "us-east-2", "AWS Region")
	roleARN        = flag.String("roleARN", "arn:aws:iam::291738886548:role/rolesanywhere1", "Role to assume")
	trustAnchorARN = flag.String("trustAnchorARN", "arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92da", "Trust Anchor ARN")
	profileARN     = flag.String("profileARN", "arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380", "Profile ARN")

	tpmPath          = flag.String("tpm-path", "127.0.0.1:2321", "TPM Path")
	persistentHandle = flag.Int("persistent-handle", 0, "persistent handle")
	tpmPrivateKey    = flag.String("keyfile", "", "tpm key file")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()

	if *persistentHandle != 0 && *tpmPrivateKey != "" {
		log.Fatalf("can't specify both persistentHandle and TPMPrivateKey")
	}
	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM  %v", err)
	}
	defer rwc.Close()
	rwr := transport.FromReadWriter(rwc)

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

	var handle tpm2.TPMHandle
	if *tpmPrivateKey != "" {
		kb, err := os.ReadFile(*tpmPrivateKey)
		if err != nil {
			log.Fatalf("can't read keyfile  %v", err)
		}
		k, err := keyfile.Decode(kb)
		if err != nil {
			log.Fatalf("can't decoding keyfile  %v", err)
		}

		// keyfile also provides a signer but here w're just using mine
		//k.Signer()

		primaryKey, err := tpm2.CreatePrimary{
			PrimaryHandle: k.Parent,
			InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("can't create primary %v", err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primaryKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		regenRSAKey, err := tpm2.Load{
			ParentHandle: tpm2.AuthHandle{
				Handle: primaryKey.ObjectHandle,
				Name:   tpm2.TPM2BName(primaryKey.Name),
				Auth:   tpm2.PasswordAuth([]byte("")),
			},
			InPublic:  k.Pubkey,
			InPrivate: k.Privkey,
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("can't loading key from keyfile  %v", err)
		}
		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: regenRSAKey.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()
		handle = regenRSAKey.ObjectHandle

	} else {
		handle = tpm2.TPMHandle(*persistentHandle)
	}

	pub, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing tpm2.ReadPublic %s", err)
	}

	s, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: rwc,
		NamedHandle: &tpm2.NamedHandle{
			Handle: handle,
			Name:   pub.Name,
		},
	})
	if err != nil {
		log.Fatalf("error getting signer %v\n", err)
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
		Signer: s,
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
	//  panic(err.Error())
	// }

	// for index, bucket := range output.Buckets {
	//  fmt.Printf("Bucket %v: %v\n", index+1, *bucket.Name)
	// }

}
