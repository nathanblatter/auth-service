package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Single-table layout; see docs/DESIGN.md "Storage".
const (
	gsi1 = "GSI1"

	pkService = "SERVICE#"
	pkSlug    = "SLUG#"
	pkAudit   = "AUDIT#"
	skMeta    = "META"
	skCred    = "CRED#"
	gsiAll    = "SERVICES"

	pkOwner     = "OWNER#me"
	skPasskey   = "PASSKEY#"
	pkChallenge = "CHALLENGE#"
	pkSession   = "SESSION#"
	pkRate      = "RATE#"
)

// DynamoAPI is the slice of the DynamoDB client the store uses.
type DynamoAPI interface {
	PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItem(ctx context.Context, in *dynamodb.GetItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	Query(ctx context.Context, in *dynamodb.QueryInput, opts ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, opts ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

// Dynamo is the DynamoDB Store.
type Dynamo struct {
	db    DynamoAPI
	table string
}

// NewDynamo wraps a client and table name.
func NewDynamo(db DynamoAPI, table string) *Dynamo { return &Dynamo{db: db, table: table} }

type serviceItem struct {
	PK, SK, GSI1PK, GSI1SK string
	Type                   string `dynamodbav:"type"`
	ID                     string `dynamodbav:"id"`
	Slug                   string `dynamodbav:"slug"`
	Name                   string `dynamodbav:"name"`
	Status                 string `dynamodbav:"status"`
	CreatedAt              string `dynamodbav:"created_at"`
}

type credItem struct {
	PK, SK, GSI1PK, GSI1SK string
	Type                   string `dynamodbav:"type"`
	ID                     string `dynamodbav:"id"`
	ServiceID              string `dynamodbav:"service_id"`
	Hash                   string `dynamodbav:"hash"`
	Last4                  string `dynamodbav:"last4"`
	CreatedAt              string `dynamodbav:"created_at"`
	RevokedAt              string `dynamodbav:"revoked_at,omitempty"`
}

func (d *Dynamo) CreateService(ctx context.Context, s Service) error {
	item, err := attributevalue.MarshalMap(serviceItem{
		PK: pkService + s.ID, SK: skMeta, GSI1PK: gsiAll, GSI1SK: s.Slug,
		Type: "service", ID: s.ID, Slug: s.Slug, Name: s.Name, Status: s.Status,
		CreatedAt: s.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	lock, err := attributevalue.MarshalMap(map[string]string{"PK": pkSlug + s.Slug, "SK": skMeta, "service_id": s.ID})
	if err != nil {
		return err
	}
	_, err = d.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{TableName: &d.table, Item: lock, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
			{Put: &types.Put{TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		},
	})
	var canceled *types.TransactionCanceledException
	if errors.As(err, &canceled) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) GetService(ctx context.Context, id string) (Service, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkService+id, skMeta)})
	if err != nil {
		return Service{}, err
	}
	if out.Item == nil {
		return Service{}, ErrNotFound
	}
	var it serviceItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return Service{}, err
	}
	return it.toService()
}

func (d *Dynamo) ListServices(ctx context.Context) ([]Service, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:                 &d.table,
		IndexName:                 aws.String(gsi1),
		KeyConditionExpression:    aws.String("GSI1PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: gsiAll}},
	})
	if err != nil {
		return nil, err
	}
	var items []serviceItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	svcs := make([]Service, 0, len(items))
	for _, it := range items {
		s, err := it.toService()
		if err != nil {
			return nil, err
		}
		svcs = append(svcs, s)
	}
	return svcs, nil
}

func (d *Dynamo) PutCredential(ctx context.Context, c Credential) error {
	item, err := attributevalue.MarshalMap(credItem{
		PK: pkService + c.ServiceID, SK: skCred + c.ID, GSI1PK: skCred + c.ID, GSI1SK: pkService + c.ServiceID,
		Type: "credential", ID: c.ID, ServiceID: c.ServiceID, Hash: c.Hash, Last4: c.Last4,
		CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) GetCredential(ctx context.Context, credID string) (Credential, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:                 &d.table,
		IndexName:                 aws.String(gsi1),
		KeyConditionExpression:    aws.String("GSI1PK = :p"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: skCred + credID}},
		Limit:                     aws.Int32(1),
	})
	if err != nil {
		return Credential{}, err
	}
	if len(out.Items) == 0 {
		return Credential{}, ErrNotFound
	}
	var it credItem
	if err := attributevalue.UnmarshalMap(out.Items[0], &it); err != nil {
		return Credential{}, err
	}
	return it.toCredential()
}

func (d *Dynamo) ListCredentials(ctx context.Context, serviceID string) ([]Credential, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("PK = :p AND begins_with(SK, :s)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": &types.AttributeValueMemberS{Value: pkService + serviceID},
			":s": &types.AttributeValueMemberS{Value: skCred},
		},
	})
	if err != nil {
		return nil, err
	}
	var items []credItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	creds := make([]Credential, 0, len(items))
	for _, it := range items {
		c, err := it.toCredential()
		if err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, nil
}

func (d *Dynamo) RevokeCredential(ctx context.Context, serviceID, credID string, at time.Time) error {
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           &d.table,
		Key:                 dynKey(pkService+serviceID, skCred+credID),
		UpdateExpression:    aws.String("SET revoked_at = if_not_exists(revoked_at, :t)"),
		ConditionExpression: aws.String("attribute_exists(PK)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":t": &types.AttributeValueMemberS{Value: at.UTC().Format(time.RFC3339Nano)},
		},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

func (d *Dynamo) AppendAudit(ctx context.Context, e AuditEvent) error {
	var r [6]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	ts := e.At.UTC().Format(time.RFC3339Nano)
	item, err := attributevalue.MarshalMap(map[string]string{
		"PK": pkAudit + e.At.UTC().Format("2006-01"), "SK": ts + "#" + hex.EncodeToString(r[:]),
		"type": "audit", "at": ts, "kind": e.Kind, "actor": e.Actor, "service_id": e.ServiceID,
		"detail": e.Detail, "ip": e.IP,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item})
	return err
}

func dynKey(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: pk},
		"SK": &types.AttributeValueMemberS{Value: sk},
	}
}

func (it serviceItem) toService() (Service, error) {
	t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
	if err != nil {
		return Service{}, fmt.Errorf("store: bad created_at on %s: %w", it.PK, err)
	}
	return Service{ID: it.ID, Slug: it.Slug, Name: it.Name, Status: it.Status, CreatedAt: t}, nil
}

func (it credItem) toCredential() (Credential, error) {
	t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
	if err != nil {
		return Credential{}, fmt.Errorf("store: bad created_at on %s/%s: %w", it.PK, it.SK, err)
	}
	c := Credential{ID: it.ID, ServiceID: it.ServiceID, Hash: it.Hash, Last4: it.Last4, CreatedAt: t}
	if it.RevokedAt != "" {
		r, err := time.Parse(time.RFC3339Nano, it.RevokedAt)
		if err != nil {
			return Credential{}, fmt.Errorf("store: bad revoked_at on %s/%s: %w", it.PK, it.SK, err)
		}
		c.RevokedAt = &r
	}
	return c, nil
}

type passkeyItem struct {
	PK, SK    string
	Type      string `dynamodbav:"type"`
	ID        string `dynamodbav:"id"`
	Name      string `dynamodbav:"name"`
	CreatedAt string `dynamodbav:"created_at"`
	Data      []byte `dynamodbav:"data"`
}

type expiringItem struct {
	PK, SK    string
	Type      string `dynamodbav:"type"`
	CreatedAt string `dynamodbav:"created_at,omitempty"`
	ExpiresAt string `dynamodbav:"expires_at"`
	IP        string `dynamodbav:"ip,omitempty"`
	Data      []byte `dynamodbav:"data,omitempty"`
	// TTL is the table's TTL attribute: DynamoDB deletes the row within ~48h
	// of this epoch second. Expiry is still enforced in code.
	TTL int64 `dynamodbav:"ttl"`
}

func (d *Dynamo) PutPasskey(ctx context.Context, p Passkey) error {
	item, err := attributevalue.MarshalMap(passkeyItem{
		PK: pkOwner, SK: skPasskey + p.ID, Type: "passkey", ID: p.ID, Name: p.Name,
		CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339Nano), Data: p.Data,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &d.table, Item: item, ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrConflict
	}
	return err
}

func (d *Dynamo) UpdatePasskey(ctx context.Context, p Passkey) error {
	if len(p.Data) == 0 {
		return errors.New("store: passkey data required")
	}
	_, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                &d.table,
		Key:                      dynKey(pkOwner, skPasskey+p.ID),
		UpdateExpression:         aws.String("SET #d = :d, #n = :n"),
		ConditionExpression:      aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames: map[string]string{"#d": "data", "#n": "name"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":d": &types.AttributeValueMemberB{Value: p.Data},
			":n": &types.AttributeValueMemberS{Value: p.Name},
		},
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		return ErrNotFound
	}
	return err
}

func (d *Dynamo) ListPasskeys(ctx context.Context) ([]Passkey, error) {
	out, err := d.db.Query(ctx, &dynamodb.QueryInput{
		TableName:              &d.table,
		KeyConditionExpression: aws.String("PK = :p AND begins_with(SK, :s)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":p": &types.AttributeValueMemberS{Value: pkOwner},
			":s": &types.AttributeValueMemberS{Value: skPasskey},
		},
	})
	if err != nil {
		return nil, err
	}
	var items []passkeyItem
	if err := attributevalue.UnmarshalListOfMaps(out.Items, &items); err != nil {
		return nil, err
	}
	keys := make([]Passkey, 0, len(items))
	for _, it := range items {
		t, err := time.Parse(time.RFC3339Nano, it.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("store: bad created_at on %s/%s: %w", it.PK, it.SK, err)
		}
		keys = append(keys, Passkey{ID: it.ID, Name: it.Name, CreatedAt: t, Data: it.Data})
	}
	return keys, nil
}

func (d *Dynamo) PutChallenge(ctx context.Context, id string, data []byte, expires time.Time) error {
	item, err := attributevalue.MarshalMap(expiringItem{
		PK: pkChallenge + id, SK: skMeta, Type: "challenge", Data: data,
		ExpiresAt: expires.UTC().Format(time.RFC3339Nano), TTL: expires.Unix() + 60,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item})
	return err
}

func (d *Dynamo) ConsumeChallenge(ctx context.Context, id string, now time.Time) ([]byte, error) {
	out, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &d.table, Key: dynKey(pkChallenge+id, skMeta), ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return nil, err
	}
	if out.Attributes == nil {
		return nil, ErrNotFound
	}
	var it expiringItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &it); err != nil {
		return nil, err
	}
	exp, err := time.Parse(time.RFC3339Nano, it.ExpiresAt)
	if err != nil || !now.Before(exp) {
		return nil, ErrNotFound
	}
	return it.Data, nil
}

func (d *Dynamo) PutSession(ctx context.Context, s Session) error {
	item, err := attributevalue.MarshalMap(expiringItem{
		PK: pkSession + s.Hash, SK: skMeta, Type: "session", IP: s.IP,
		CreatedAt: s.CreatedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: s.ExpiresAt.UTC().Format(time.RFC3339Nano), TTL: s.ExpiresAt.Unix() + 60,
	})
	if err != nil {
		return err
	}
	_, err = d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item})
	return err
}

func (d *Dynamo) GetSession(ctx context.Context, hash string, now time.Time) (Session, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkSession+hash, skMeta)})
	if err != nil {
		return Session{}, err
	}
	if out.Item == nil {
		return Session{}, ErrNotFound
	}
	var it expiringItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return Session{}, err
	}
	exp, err := time.Parse(time.RFC3339Nano, it.ExpiresAt)
	if err != nil || !now.Before(exp) {
		return Session{}, ErrNotFound
	}
	created, _ := time.Parse(time.RFC3339Nano, it.CreatedAt)
	return Session{Hash: hash, CreatedAt: created, ExpiresAt: exp, IP: it.IP}, nil
}

func (d *Dynamo) DeleteSession(ctx context.Context, hash string) error {
	_, err := d.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &d.table, Key: dynKey(pkSession+hash, skMeta)})
	return err
}

type rateItem struct {
	PK, SK string
	Type   string `dynamodbav:"type"`
	Count  int    `dynamodbav:"count"`
	Until  int64  `dynamodbav:"until"` // epoch seconds the window ends
	TTL    int64  `dynamodbav:"ttl"`
}

func (d *Dynamo) FailureCount(ctx context.Context, key string, now time.Time) (int, error) {
	out, err := d.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &d.table, Key: dynKey(pkRate+key, skMeta)})
	if err != nil {
		return 0, err
	}
	if out.Item == nil {
		return 0, nil
	}
	var it rateItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return 0, err
	}
	if now.Unix() >= it.Until {
		return 0, nil
	}
	return it.Count, nil
}

// RecordFailure increments the counter inside a live window, or starts a new
// window when none is live. Two steps, both conditional, so concurrent
// failures never lose a count.
func (d *Dynamo) RecordFailure(ctx context.Context, key string, now time.Time, window time.Duration) (int, error) {
	out, err := d.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                &d.table,
		Key:                      dynKey(pkRate+key, skMeta),
		UpdateExpression:         aws.String("ADD #c :one"),
		ConditionExpression:      aws.String("attribute_exists(PK) AND #u > :now"),
		ExpressionAttributeNames: map[string]string{"#c": "count", "#u": "until"},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one": &types.AttributeValueMemberN{Value: "1"},
			":now": &types.AttributeValueMemberN{Value: fmt.Sprint(now.Unix())},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	var cond *types.ConditionalCheckFailedException
	if errors.As(err, &cond) {
		// No live window: start one at 1.
		until := now.Add(window).Unix()
		item, err := attributevalue.MarshalMap(rateItem{PK: pkRate + key, SK: skMeta, Type: "rate", Count: 1, Until: until, TTL: until + 60})
		if err != nil {
			return 0, err
		}
		if _, err := d.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: &d.table, Item: item}); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	var it rateItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &it); err != nil {
		return 0, err
	}
	return it.Count, nil
}
