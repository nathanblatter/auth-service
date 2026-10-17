// Command api is the Squawk HTTP API. Inside Lambda it serves API
// Gateway v2 events; anywhere else it listens on $PORT.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"

	"github.com/nathanblatter/squawk/internal/config"
	"github.com/nathanblatter/squawk/internal/core"
	"github.com/nathanblatter/squawk/internal/httpapi"
	"github.com/nathanblatter/squawk/internal/mailqueue"
	"github.com/nathanblatter/squawk/internal/oauth"
	"github.com/nathanblatter/squawk/internal/owner"
	"github.com/nathanblatter/squawk/internal/ratelimit"
	"github.com/nathanblatter/squawk/internal/signer"
	"github.com/nathanblatter/squawk/internal/store"
	"github.com/nathanblatter/squawk/internal/users"
)

// version is set by the Makefile via -ldflags.
var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	handler, cfg, err := build(context.Background(), log)
	if err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}
	log.Info("squawk starting", "version", version, "config", cfg.String(), "lambda", config.InLambda())

	if config.InLambda() {
		lambda.Start(httpadapter.NewV2(handler).ProxyWithContext)
		return
	}
	srv := &http.Server{
		Addr: ":" + cfg.Port, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second,
	}
	log.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// build resolves config and wires every dependency.
func build(ctx context.Context, log *slog.Logger) (http.Handler, config.Config, error) {
	cfg, err := config.FromEnv(version)
	if err != nil {
		return nil, cfg, err
	}

	awsOpts := []func(*awsconfig.LoadOptions) error{}
	if cfg.DynamoEndpoint != "" {
		// DynamoDB Local accepts any static credentials.
		awsOpts = append(awsOpts,
			awsconfig.WithRegion("us-east-1"),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("local", "local", "")))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return nil, cfg, fmt.Errorf("aws config: %w", err)
	}

	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if cfg.DynamoEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.DynamoEndpoint)
		}
	})
	if cfg.DynamoEndpoint != "" {
		if err := store.CreateTable(ctx, ddb, cfg.Table); err != nil {
			return nil, cfg, fmt.Errorf("create local table: %w", err)
		}
	}
	st := store.NewDynamo(ddb, cfg.Table)

	ring, err := buildRing(ctx, cfg, kms.NewFromConfig(awsCfg))
	if err != nil {
		return nil, cfg, err
	}

	ssmClient := ssm.NewFromConfig(awsCfg)
	readParam := func(name string) (string, error) {
		out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(name), WithDecryption: aws.Bool(true)})
		if err != nil {
			return "", fmt.Errorf("read ssm %s: %w", name, err)
		}
		return aws.ToString(out.Parameter.Value), nil
	}
	adminHash := ""
	switch {
	case cfg.AdminToken != "":
		adminHash = core.HashSecret(cfg.AdminToken)
	case cfg.AdminTokenHashParam != "":
		if adminHash, err = readParam(cfg.AdminTokenHashParam); err != nil {
			return nil, cfg, err
		}
	}
	var google *users.Google
	if cfg.GoogleClientID != "" {
		secret := cfg.GoogleClientSecret
		if cfg.GoogleClientSecretParam != "" {
			if secret, err = readParam(cfg.GoogleClientSecretParam); err != nil {
				// A missing secret must not take the whole API down; Google login stays off.
				log.Error("google client secret unavailable; Sign in with Google disabled", "err", err)
				secret = ""
			}
		}
		if secret != "" {
			google = users.NewGoogle(cfg.GoogleClientID, secret, cfg.Issuer+"/v1/login/google/callback")
		}
	}

	c := core.New(st, ring, cfg.Issuer)
	c.Log = log
	own, err := owner.New(st, cfg.Issuer)
	if err != nil {
		return nil, cfg, err
	}
	own.Log = log
	lim := ratelimit.New(st)
	lim.Log = log
	us := users.New(st)
	us.Log = log
	us.AlertAllowed = func(ctx context.Context, userID string) bool {
		key := "alert:" + userID
		if !lim.Allow(ctx, ratelimit.LoginAlert, key) {
			return false
		}
		lim.Fail(ctx, ratelimit.LoginAlert, key) // counts sends
		return true
	}
	if cfg.MailQueueURL != "" {
		us.Mail = &mailqueue.SQS{Client: sqs.NewFromConfig(awsCfg), QueueURL: cfg.MailQueueURL}
	} else {
		log.Warn("AUTH_MAIL_QUEUE_URL unset; email codes and verification disabled")
	}
	srv := &httpapi.Server{Core: c, Owner: own, Limit: lim, OAuth: oauth.New(c), Users: us, Google: google, AdminTokenHash: adminHash, Log: log, Version: version}
	return srv.Handler(), cfg, nil
}

func buildRing(ctx context.Context, cfg config.Config, kmsClient *kms.Client) (*signer.Ring, error) {
	if cfg.LocalSigner {
		s, err := signer.NewLocal("local-" + time.Now().UTC().Format("20060102T150405"))
		if err != nil {
			return nil, err
		}
		return signer.NewRing(s)
	}
	signers := make([]signer.Signer, 0, len(cfg.SigningKeyIDs))
	for _, id := range cfg.SigningKeyIDs {
		s, err := signer.NewKMS(ctx, kmsClient, id)
		if err != nil {
			return nil, err
		}
		signers = append(signers, s)
	}
	return signer.NewRing(signers...)
}
