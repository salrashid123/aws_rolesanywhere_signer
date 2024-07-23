package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	helper "github.com/aws/rolesanywhere-credential-helper/aws_signing_helper"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	rolesanywhere "github.com/salrashid123/aws_rolesanywhere_signer"
)

//const socketPath = "tcp://127.0.0.1:8081"

// export REGION=us-east-2
// export CERT_PATH=/tmp/svid.0.pem
// export ROLE_ARN=arn:aws:iam::291738886548:role/spiffierole1
// export TRUST_ANCHOR_ARN=arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/572e4711-1d8d-4fb8-be0f-7b1aa57ca4f0
// export PROFILE_ARN=arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380

// /tmp/aws_signing_helper credential-process \
//     --certificate $CERT_PATH \
//     --private-key /tmp/svid.0.key \
//     --role-arn $ROLE_ARN \
//     --trust-anchor-arn $TRUST_ANCHOR_ARN \
//     --profile-arn $PROFILE_ARN

var (
	socketPath     = flag.String("socketPath", "", "socket path (SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock)")
	bundlePath     = flag.String("bundlePath", "", "x509 certificate bundle")
	awsRegion      = flag.String("awsRegion", "us-east-2", "AWS Region")
	roleARN        = flag.String("roleARN", "arn:aws:iam::291738886548:role/spiffierole1", "Role to assume")
	trustAnchorARN = flag.String("trustAnchorARN", "arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/572e4711-1d8d-4fb8-be0f-7b1aa57ca4f0", "Trust Anchor ARN")
	profileARN     = flag.String("profileARN", "arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380", "Profile ARN")
)

func main() {
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())

	// Wait for an os.Interrupt signal
	go waitForCtrlC(cancel)

	// Start X.509 and JWT watchers
	startWatchers(ctx)
}

func startWatchers(ctx context.Context) {
	var wg sync.WaitGroup

	// Creates a new Workload API client, connecting to provided socket path
	// Environment variable `SPIFFE_ENDPOINT_SOCKET` is used as default
	var client *workloadapi.Client
	var err error
	if *socketPath != "" {
		client, err = workloadapi.New(ctx, workloadapi.WithAddr(*socketPath))
	} else {
		client, err = workloadapi.New(ctx)
	}
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	wg.Add(1)
	// Start a watcher for X.509 SVID updates
	go func() {
		defer wg.Done()
		err := client.WatchX509Context(ctx, &x509Watcher{})
		if err != nil && status.Code(err) != codes.Canceled {
			log.Fatalf("Error watching X.509 context: %v", err)
		}
	}()

	wg.Add(1)
	// Start a watcher for JWT bundle updates
	go func() {
		defer wg.Done()
		err := client.WatchJWTBundles(ctx, &jwtWatcher{})
		if err != nil && status.Code(err) != codes.Canceled {
			log.Fatalf("Error watching JWT bundles: %v", err)
		}
	}()

	wg.Wait()
}

// x509Watcher is a sample implementation of the workloadapi.X509ContextWatcher interface
type x509Watcher struct{}

// UpdateX509SVIDs is run every time an SVID is updated
func (x509Watcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	for _, svid := range c.SVIDs {
		ppem, pkey, err := svid.Marshal()
		if err != nil {
			log.Fatalf("Unable to marshal X.509 SVID: %v", err)
		}

		log.Printf("SVID updated for %q: \n%s\n", svid.ID, string(ppem))
		log.Printf("SVID  key updated for %q: \n%s\n", svid.ID, string(pkey))

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
		if ppem != nil {
			var err error

			block, _ := pem.Decode([]byte(ppem))

			cert, err = x509.ParseCertificate(block.Bytes)
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

		block, _ := pem.Decode(pkey)
		parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Printf("error reading private key %v", err)
			return
		}

		var key crypto.Signer

		switch parseResult.(type) {
		case *rsa.PrivateKey:
			key = parseResult.(*rsa.PrivateKey)
		case *ecdsa.PrivateKey:
			key = parseResult.(*ecdsa.PrivateKey)
		default:
			log.Printf("error unsupported key ttype private key %v", err)
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
		// 	fmt.Printf("Could not read bucket contents %v\n", err)
		// 	return
		// }

		// for index, bucket := range output.Buckets {
		// 	fmt.Printf("Bucket %v: %v\n", index+1, *bucket.Name)
		// }

	}
}

// OnX509ContextWatchError is run when the client runs into an error
func (x509Watcher) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Printf("OnX509ContextWatchError error: %v", err)
	}
}

// jwtWatcher is a sample implementation of the workloadapi.JWTBundleWatcher interface
type jwtWatcher struct{}

// UpdateX509SVIDs is run every time a JWT Bundle is updated
func (jwtWatcher) OnJWTBundlesUpdate(bundleSet *jwtbundle.Set) {
	for _, bundle := range bundleSet.Bundles() {
		jwt, err := bundle.Marshal()
		if err != nil {
			log.Fatalf("Unable to marshal JWT Bundle : %v", err)
		}
		log.Printf("jwt bundle updated %q: %s", bundle.TrustDomain(), string(jwt))
	}
}

// OnJWTBundlesWatchError is run when the client runs into an error
func (jwtWatcher) OnJWTBundlesWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Printf("OnJWTBundlesWatchError error: %v", err)
	}
}

// waitForCtrlC waits until an os.Interrupt signal is sent (ctrl + c)
func waitForCtrlC(cancel context.CancelFunc) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	<-signalCh

	cancel()
}
