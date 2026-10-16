package mailqueue

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type fake struct {
	in  *sqs.SendMessageInput
	err error
}

func (f *fake) SendMessage(_ context.Context, in *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.in = in
	return &sqs.SendMessageOutput{}, f.err
}

func TestSend(t *testing.T) {
	f := &fake{}
	q := &SQS{Client: f, QueueURL: "https://sqs/q"}
	if err := q.Send(context.Background(), "a@x.test", "Subj", "Body"); err != nil {
		t.Fatal(err)
	}
	var m Message
	if err := json.Unmarshal([]byte(*f.in.MessageBody), &m); err != nil || *f.in.QueueUrl != "https://sqs/q" {
		t.Fatalf("body: %s %v", *f.in.MessageBody, err)
	}
	if m.To != "a@x.test" || m.Subject != "Subj" || m.Text != "Body" || m.From != "" {
		t.Fatalf("message: %+v", m)
	}
	f.err = errors.New("boom")
	if err := q.Send(context.Background(), "a@x.test", "s", "t"); err == nil {
		t.Fatal("sqs error must surface")
	}
}
