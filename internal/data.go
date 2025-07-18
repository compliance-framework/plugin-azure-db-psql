package internal

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

type AzureDataProcessor struct {
	ctx       context.Context
	logger    hclog.Logger
	config    map[string]string
	apiHelper runner.ApiHelper
}

func NewAzureDataProcessor(ctx context.Context, logger hclog.Logger, config map[string]string, apiHelper runner.ApiHelper) *AzureDataProcessor {
	return &AzureDataProcessor{
		ctx:       ctx,
		logger:    logger,
		config:    config,
		apiHelper: apiHelper,
	}
}

// Get the data from Azure, evaluate that data against policies and send to the API
func (dp *AzureDataProcessor) Process(policyPaths []string) (proto.ExecutionStatus, error) {
	evalStatus := proto.ExecutionStatus_SUCCESS
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	activities = append(activities, &proto.Activity{
		Title:       "Collect Azure Postgres Flexible Servers",
		Description: "Collect Azure Postgres Flexible Server configurations using the Azure SDK for Go.",
		Steps: []*proto.Step{
			{
				Title:       "Initialize Azure SDK",
				Description: "Initialize the Azure SDK with the provided credentials and subscription ID.",
			},
			{
				Title:       "List Flexible PostgreSQL Servers",
				Description: "List all Azure Flexible PostgreSQL Servers in the specified subscription.",
			},
		},
	})

	for server, err := range dp.GetPostgresFlexibleServers() {
		if err != nil {
			dp.logger.Error("Error retrieving Azure PostgreSQL servers", "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			break
		}

		idparts, err := ParseAzureResourceID(*server.ID)
		if err != nil {
			dp.logger.Error("Error parsing Azure resource ID", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			continue
		}

		labels := map[string]string{
			"provider":        "azure",
			"type":            "database",
			"instance-id":     *server.ID,
			"resource-group":  idparts["resourceGroups"],
			"location":        normaliseLocation(*server.Location),
			"name":            *server.Name,
			"subscription_id": idparts["subscriptions"],
		}

		actors := []*proto.OriginActor{
			{
				Title: "The Continuous Compliance Framework",
				Type:  "assessment-platform",
				Links: []*proto.Link{
					{
						Href: "https://compliance-framework.github.io/docs/",
						Rel:  StringAddressed("reference"),
						Text: StringAddressed("The Continuous Compliance Framework"),
					},
				},
			},
			{
				Title: "Continuous Compliance Framework - Azure DB PSQL Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-azure-db-psql",
						Rel:  StringAddressed("reference"),
						Text: StringAddressed("The Continuous Compliance Framework's Azure DB PSQL Plugin"),
					},
				},
			},
		}

		components := []*proto.Component{
			{
				Identifier:  "common-components/az-postgres-database",
				Title:       "Azure PostgreSQL Database",
				Description: "A PostgreSQL database hosted on Azure, managed by the Azure PostgreSQL Flexible Servers service.",
				Purpose:     "To provide a managed PostgreSQL database service on Azure.",
			},
		}

		inventory := []*proto.InventoryItem{
			{
				Identifier: fmt.Sprintf("azure-postgres-database/%s", *server.ID),
				Type:       "database",
				Title:      *server.Name,
				Props: []*proto.Property{
					{
						Name:  "vm-id",
						Value: *server.ID,
					},
					{
						Name:  "vm-name",
						Value: *server.Name,
					},
				},
			},
		}

		subjects := []*proto.Subject{
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
				Identifier: "common-components/az-postgres-database",
			},
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
				Identifier: fmt.Sprintf("azure-postgres-database/%s", *server.ID),
			},
		}

		evidences := make([]*proto.Evidence, 0)
		for _, policyPath := range policyPaths {
			processor := policyManager.NewPolicyProcessor(
				dp.logger,
				labels,
				subjects,
				components,
				inventory,
				actors,
				activities,
			)

			evidence, err := processor.GenerateResults(dp.ctx, policyPath, server)
			evidences = append(evidences, evidence...)

			if err != nil {
				dp.logger.Error("Error processing policy", "policyPath", policyPath, "error", err)
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}

		if err := dp.apiHelper.CreateEvidence(dp.ctx, evidences); err != nil {
			dp.logger.Error("Error creating evidence", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			evalStatus = proto.ExecutionStatus_FAILURE
			continue
		}
	}

	return evalStatus, accumulatedErrors
}

func (dp *AzureDataProcessor) GetPostgresFlexibleServers() iter.Seq2[*armpostgresqlflexibleservers.Server, error] {
	return func(yield func(*armpostgresqlflexibleservers.Server, error) bool) {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			dp.logger.Error("unable to get Azure credentials", "error", err)
			yield(nil, err)
			return
		}
		dp.logger.Debug("Azure credentials obtained successfully")

		client, err := armpostgresqlflexibleservers.NewServersClient(dp.config["subscription_id"], cred, nil)
		if err != nil {
			dp.logger.Error("unable to create Azure PostgreSQL client", "error", err)
			yield(nil, err)
			return
		}

		dp.logger.Debug("Azure PostgreSQL client created successfully", "client", client)

		pager := client.NewListPager(nil)

		for pager.More() {
			page, err := pager.NextPage(dp.ctx)
			if err != nil {
				dp.logger.Error("unable to list Azure PostgreSQL servers", "error", err)
				yield(nil, err)
				return
			}

			for _, server := range page.Value {
				if !yield(server, nil) {
					return
				}
			}
		}
	}
}
