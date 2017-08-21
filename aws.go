package main

import "strings"
import "errors"
import "fmt"
import "time"
import "os/user"
import "github.com/tj/go-debug"
import "github.com/aws/aws-sdk-go/aws"
import "github.com/aws/aws-sdk-go/aws/credentials"
import "github.com/aws/aws-sdk-go/aws/session"
import "github.com/aws/aws-sdk-go/service/sts"

var debugAws = debug.Debug("oktad:aws")

type SamlProviderArns struct {
	PrincipalArn string
	RoleArn      string
}

// assumes the first role and returns the credentials you need for
// the second assumeRole...
// returns those credentials, the expiration time, and error if any
func assumeFirstRole(acfg AwsConfig, saml *OktaSamlResponse) (*credentials.Credentials, time.Time, error) {
	var emptyExpire time.Time
	sess := session.New(
		aws.NewConfig().WithRegion(acfg.Region),
	)
	scl := sts.New(
		sess,
	)

	var arns *SamlProviderArns
	var found bool = false
	var err error

	for _, a := range saml.Attributes {
		if a.Name == "https://aws.amazon.com/SAML/Attributes/Role" {
			var crossAccountArn string
			if acfg.CrossAcctArn != "" {
				crossAccountArn = acfg.CrossAcctArn
			} else {
				crossAccountArn, err = selectCrossAccount(a.Value)

				if err != nil {
					return nil, emptyExpire, err
				}
			}

			for _, v := range a.Value {
				arns, err = splitSamlProviderArns(v)

				if err != nil {
					return nil, emptyExpire, err
				}

				debugAws("found principal ARN: %s, role ARN: %s", arns.PrincipalArn, arns.RoleArn)

				if crossAccountArn == arns.RoleArn {
					found = true
					break
				}
			}
		}
	}

	if !found {
		return nil, emptyExpire, errors.New("no arn found from saml data!")
	}

	res, err := scl.AssumeRoleWithSAML(
		&sts.AssumeRoleWithSAMLInput{
			PrincipalArn:    &arns.PrincipalArn,
			RoleArn:         &arns.RoleArn,
			SAMLAssertion:   &saml.raw,
			DurationSeconds: aws.Int64(3600),
		},
	)

	if err != nil {
		debugAws("error in AssumeRoleWithSAML")
		return nil, emptyExpire, err
	}

	mCreds := credentials.NewStaticCredentials(
		*res.Credentials.AccessKeyId,
		*res.Credentials.SecretAccessKey,
		*res.Credentials.SessionToken,
	)

	return mCreds, *res.Credentials.Expiration, nil
}

// behold, the moment we've been waiting for!
// we need to assume role into the second account...
// this will require the AwsConfig, which includes the final
// destination ARN, and some AWS credentials that allow us to do that
func assumeDestinationRole(acfg AwsConfig, creds *credentials.Credentials) (*credentials.Credentials, time.Time, error) {
	var emptyExpire time.Time
	sess := session.New(
		aws.NewConfig().
			WithRegion(acfg.Region).
			WithCredentials(creds),
	)
	scl := sts.New(
		sess,
	)

	var sessionName string
	if user, err := user.Current(); err == nil {
		sessionName = user.Username
	} else {
		debugAws("error getting username from OS: %s", err)
		sessionName = "unknown-user"
	}

	res, err := scl.AssumeRole(
		&sts.AssumeRoleInput{
			RoleArn:         &acfg.DestArn,
			RoleSessionName: &sessionName,
		},
	)

	if err != nil {
		debugAws("error in assumeDestinationRole! you were so close!")
		return nil, emptyExpire, err
	}

	mCreds := credentials.NewStaticCredentials(
		*res.Credentials.AccessKeyId,
		*res.Credentials.SecretAccessKey,
		*res.Credentials.SessionToken,
	)

	return mCreds, *res.Credentials.Expiration, nil
}

func splitSamlProviderArns(arns string) (*SamlProviderArns, error) {
	var res SamlProviderArns
	parts := strings.Split(arns, ",")

	if len(parts) != 2 {
		return nil, errors.New("invalid SAML Provider ARN")
	}

	for _, part := range parts {
		if strings.Contains(part, "saml-provider") {
			res.PrincipalArn = part
		} else {
			res.RoleArn = part
		}
	}

	return &res, nil
}

func selectCrossAccount(values []string) (crossAccountArn string, err error) {
	choices := len(values)
	if choices < 1 {
		return "", errors.New("empty array of cross-account ARNs received")
	}

	if choices == 1 {
		return values[0], nil
	}

	var arns []string
	fmt.Println("Roles available: ")
	for i, a := range values {
		debugAws("index: %d, value: %s", i, a)
		arn, _ := splitSamlProviderArns(a)
		arns = append(arns, arn.RoleArn)
		debugAws("arn.RoleArn: %s", arn.RoleArn)
		fmt.Println(i, "- ", arns[i])
	}
	fmt.Println("Select cross-account ARN number: ")
	var roleIndex int
	tries := 0

TRYROLE:
	_, err = fmt.Scanf("%d", &roleIndex)
	if err != nil {
		return "", err
	}

	if roleIndex < choices {
		debugAws("selected cross-account Arn %s", arns[roleIndex])
		return arns[roleIndex], nil
	}

	if tries < 2 {
		tries++
		fmt.Println("Invalid role number, please try again")
		goto TRYROLE
	}

	return "", errors.New("Invalid role selection. Aborting")
}
