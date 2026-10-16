// Package mailqueue is the outbox: auth-service never talks SMTP or to a
// provider. It drops {to, subject, text} on an SQS queue that the email-api
// bridge on Nathan's Mac mini drains and turns into keyed /send calls, so
// every message still leaves through email-api with an actor on it.
package mailqueue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

// Message is the wire contract with email-api's sqs-bridge.
type Message struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
	From    string `json:"from,omitempty"`
}

// Sender is the subset of the SQS client we use.
type Sender interface {
	SendMessage(ctx context.Context, in *sqs.SendMessageInput, opts ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
}

// SQS enqueues mail.
type SQS struct {
	Client   Sender
	QueueURL string
}

// Send enqueues one message.
func (s *SQS) Send(ctx context.Context, to, subject, text string) error {
	body, err := json.Marshal(Message{To: to, Subject: subject, Text: text})
	if err != nil {
		return err
	}
	if _, err := s.Client.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: aws.String(s.QueueURL), MessageBody: aws.String(string(body))}); err != nil {
		return fmt.Errorf("mailqueue: enqueue: %w", err)
	}
	return nil
}
