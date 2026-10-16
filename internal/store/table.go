package store

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// CreateTable makes the single table with its GSI. Production uses the SAM
// template; this exists for DynamoDB Local in `make dev` and the tests.
func CreateTable(ctx context.Context, client *dynamodb.Client, table string) error {
	_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   &table,
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("PK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("SK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("GSI1PK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("GSI1SK"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{{
			IndexName: aws.String(gsi1),
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("GSI1PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("GSI1SK"), KeyType: types.KeyTypeRange},
			},
			Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
		}},
	})
	var exists *types.ResourceInUseException
	if err != nil && errors.As(err, &exists) {
		return nil
	}
	return err
}
