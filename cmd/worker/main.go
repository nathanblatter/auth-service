// Command worker consumes the background-job queue. Slice 1 only logs each
// job; slice 2 adds the email jobs (verification, new-login alerts) that call
// email-api.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// Job is the envelope every queue message uses.
type Job struct {
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	lambda.Start(func(ctx context.Context, ev events.SQSEvent) (events.SQSEventResponse, error) {
		var failures []events.SQSBatchItemFailure
		for _, rec := range ev.Records {
			if err := handle(ctx, log, rec); err != nil {
				log.Error("job failed", "id", rec.MessageId, "err", err)
				failures = append(failures, events.SQSBatchItemFailure{ItemIdentifier: rec.MessageId})
			}
		}
		return events.SQSEventResponse{BatchItemFailures: failures}, nil
	})
}

func handle(_ context.Context, log *slog.Logger, rec events.SQSMessage) error {
	var job Job
	if err := json.Unmarshal([]byte(rec.Body), &job); err != nil {
		return err
	}
	log.Info("job received", "kind", job.Kind, "id", rec.MessageId)
	return nil
}
