// Package config reads the process environment. Every knob is an AUTH_* env
// var; the SAM template sets them in prod and .env sets them locally.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	// Issuer is the public base URL, e.g. https://squawk.nathanblatter.com.
	Issuer string
	// Table is the DynamoDB table name.
	Table string
	// DynamoEndpoint overrides the DynamoDB endpoint (DynamoDB Local).
	DynamoEndpoint string
	// SigningKeyIDs lists KMS key ids; the first signs. Ignored when LocalSigner.
	SigningKeyIDs []string
	// LocalSigner uses a throwaway in-memory key instead of KMS (dev only).
	LocalSigner bool
	// AdminToken is the plain interim admin token (dev only).
	AdminToken string
	// AdminTokenHashParam is the SSM parameter holding the hex SHA-256 of the admin token.
	AdminTokenHashParam string
	// GoogleClientID enables Sign in with Google when set (with the secret).
	GoogleClientID string
	// GoogleClientSecret (dev) or GoogleClientSecretParam (SSM, prod).
	GoogleClientSecret      string
	GoogleClientSecretParam string
	// MailQueueURL is the SQS outbox the email-api bridge drains; empty
	// disables every email feature (codes, verification).
	MailQueueURL string
	// Port for the local HTTP listener.
	Port string
	// Version is the build id baked in by the Makefile.
	Version string
}

// FromEnv reads and validates the environment.
func FromEnv(version string) (Config, error) {
	c := Config{
		Issuer:                  strings.TrimRight(os.Getenv("AUTH_ISSUER"), "/"),
		Table:                   os.Getenv("AUTH_TABLE"),
		DynamoEndpoint:          os.Getenv("AUTH_DYNAMO_ENDPOINT"),
		LocalSigner:             os.Getenv("AUTH_LOCAL_SIGNER") == "1",
		AdminToken:              os.Getenv("AUTH_ADMIN_TOKEN"),
		AdminTokenHashParam:     os.Getenv("AUTH_ADMIN_TOKEN_HASH_PARAM"),
		GoogleClientID:          os.Getenv("AUTH_GOOGLE_CLIENT_ID"),
		GoogleClientSecret:      os.Getenv("AUTH_GOOGLE_CLIENT_SECRET"),
		GoogleClientSecretParam: os.Getenv("AUTH_GOOGLE_CLIENT_SECRET_PARAM"),
		MailQueueURL:            os.Getenv("AUTH_MAIL_QUEUE_URL"),
		Port:                    os.Getenv("PORT"),
		Version:                 version,
	}
	for _, id := range strings.Split(os.Getenv("AUTH_SIGNING_KEY_IDS"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			c.SigningKeyIDs = append(c.SigningKeyIDs, id)
		}
	}
	if c.Port == "" {
		c.Port = "4400"
	}
	var problems []string
	if c.Issuer == "" {
		problems = append(problems, "AUTH_ISSUER is required")
	}
	if c.Table == "" {
		problems = append(problems, "AUTH_TABLE is required")
	}
	if !c.LocalSigner && len(c.SigningKeyIDs) == 0 {
		problems = append(problems, "AUTH_SIGNING_KEY_IDS is required unless AUTH_LOCAL_SIGNER=1")
	}
	if c.AdminToken != "" && c.AdminTokenHashParam != "" {
		problems = append(problems, "set AUTH_ADMIN_TOKEN (dev) or AUTH_ADMIN_TOKEN_HASH_PARAM (prod), not both")
	}
	if c.GoogleClientSecret != "" && c.GoogleClientSecretParam != "" {
		problems = append(problems, "set AUTH_GOOGLE_CLIENT_SECRET (dev) or AUTH_GOOGLE_CLIENT_SECRET_PARAM (prod), not both")
	}
	if len(problems) > 0 {
		return Config{}, errors.New("config: " + strings.Join(problems, "; "))
	}
	return c, nil
}

// InLambda reports whether the process is running inside AWS Lambda.
func InLambda() bool { return os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" }

// String is a redacted summary for startup logs.
func (c Config) String() string {
	return fmt.Sprintf("issuer=%s table=%s keys=%d local_signer=%v admin=%s google=%v",
		c.Issuer, c.Table, len(c.SigningKeyIDs), c.LocalSigner, c.adminMode(), c.GoogleClientID != "")
}

func (c Config) adminMode() string {
	switch {
	case c.AdminTokenHashParam != "":
		return "ssm:" + c.AdminTokenHashParam
	case c.AdminToken != "":
		return "env"
	default:
		return "disabled"
	}
}
