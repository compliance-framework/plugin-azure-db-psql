package internal

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type DBPager = runtime.Pager[armpostgresqlflexibleservers.ServersClientListResponse]

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type AzureDataProcessor struct {
	ctx          context.Context
	logger       hclog.Logger
	config       map[string]string
	apiHelper    runner.ApiHelper
	collectSteps []*proto.Step
	startTime    time.Time
}

func NewAzureDataProcessor(ctx context.Context, logger hclog.Logger, config map[string]string, apiHelper runner.ApiHelper) *AzureDataProcessor {
	return &AzureDataProcessor{
		ctx:          ctx,
		logger:       logger,
		config:       config,
		apiHelper:    apiHelper,
		collectSteps: make([]*proto.Step, 0),
	}
}

// Get the data from Azure, evaluate that data against policies and send to the API
func (dp *AzureDataProcessor) Process(policyPaths []string) (proto.ExecutionStatus, error) {
	dp.startTime = time.Now()

	// Get the Azure database paginator
	pager, err := dp.GetAzurePostgresPaginator()
	if err != nil {
		dp.logger.Error("Unable to get Azure Postgres data", "error", err)
		return proto.ExecutionStatus_FAILURE, err
	}

	err = dp.ProcessPaginator(pager, policyPaths)

	if err != nil {
		dp.logger.Error("Failed to process paginator", "error", err)
		return proto.ExecutionStatus_FAILURE, err
	}

	return proto.ExecutionStatus_SUCCESS, nil
}

func (dp *AzureDataProcessor) GetAzurePostgresPaginator() (*DBPager, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		dp.logger.Error("unable to get Azure credentials", "error", err)
		return nil, err
	}

	dp.collectSteps = append(dp.collectSteps, &proto.Step{
		Title:       "Fetch Azure credentials",
		Description: "Fetch Azure credentials ready to get Postgres Databases paginator.",
		Remarks:     stringAddressed("The golang library `github.com/Azure/azure-sdk-for-go/sdk/azidentity` and function `NewDefaultAzureCredential` is used to get Azure credentials."),
	})
	dp.logger.Debug("Azure credentials obtained successfully")

	client, err := armpostgresqlflexibleservers.NewServersClient(os.Getenv("AZURE_SUBSCRIPTION_ID"), cred, nil)
	if err != nil {
		dp.logger.Error("unable to create Azure PostgreSQL client", "error", err)
		return nil, err
	}

	dp.collectSteps = append(dp.collectSteps, &proto.Step{
		Title:       "Get Azure Postgres Databases client",
		Description: "Get Azure Postgres Databases client ready to create a paginator to loop through all instances.",
		Remarks:     stringAddressed(fmt.Sprintf("The golang library `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers` and function `NewServersClient` is used to get the client. The Azure subscription ID is set to %s based on the AZURE_SUBSCRIPTION_ID environment variable.", os.Getenv("AZURE_SUBSCRIPTION_ID"))),
	})
	dp.logger.Debug("Azure PostgreSQL client created successfully", "client", client)

	// Get instances
	pager := client.NewListPager(nil)

	dp.collectSteps = append(dp.collectSteps, &proto.Step{
		Title:       "Get Azure Postgres Databases paginator",
		Description: "Get Azure Postgres Databases paginator to loop through all instances.",
		Remarks:     stringAddressed("The `NewListPage` function was called on the client to get the paginator."),
	})

	return pager, err
}

func (dp *AzureDataProcessor) ProcessPaginator(pager *DBPager, policyPaths []string) error {
	var accumulatedErrors error

	for pager.More() {
		page, err := pager.NextPage(dp.ctx)

		if err != nil {
			dp.logger.Error("unable to list instances", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			break
		}

		// Parse instances
		if page.Value == nil {
			dp.logger.Error("no instances found")
			accumulatedErrors = errors.Join(accumulatedErrors, errors.New("no instances found"))
			break
		}

		dp.logger.Debug("Instances", page.Value)

		for _, instance := range page.Value {
			collectSteps := make([]*proto.Step, len(dp.collectSteps))
			_ = copy(collectSteps, dp.collectSteps)

			activities := make([]*proto.Activity, 0)

			collectSteps = append(collectSteps, &proto.Step{
				Title:       "Get Azure Postgres Database Instance",
				Description: "Get Azure Postgres Database Instance from the current page.",
				Remarks:     stringAddressed("The `NextPage` function was called on the paginator to get the next page."),
			})

			activities = append(activities, &proto.Activity{
				Title:       "Collect Postgres Databases data from Azure",
				Description: "Collect Postgres Databases data from Azure, and prepare collected data for validation in policy engine",
				Steps:       collectSteps,
			})

			var tags []Tag
			for key, value := range instance.Tags {
				tags = append(tags, Tag{Key: key, Value: *value})
			}

			// Append instanceData to list with all data from Azure API
			instanceData := map[string]any{
				"InstanceID": *instance.ID,
				"Location":   *instance.Location,
				"Name":       *instance.Name,
				"Properties": map[string]any{
					"fullyQualifiedDomainName": instance.Properties.FullyQualifiedDomainName,
					"version":                  instance.Properties.Version,
					"administratorLogin":       instance.Properties.AdministratorLogin,
					"backup":                   instance.Properties.Backup,
					"availabilityZone":         instance.Properties.AvailabilityZone,
					"highAvailability":         instance.Properties.HighAvailability,
					"maintenanceWindow":        instance.Properties.MaintenanceWindow,
					"network":                  instance.Properties.Network,
					"state":                    instance.Properties.State,
					"storage":                  instance.Properties.Storage,
				},
				"Tags": tags,
				"Type": *instance.Type,
			}

			for _, policyPath := range policyPaths {
				err := dp.ProcessInstanceAndPolicy(policyPath, instanceData, activities)
				if err != nil {
					accumulatedErrors = errors.Join(accumulatedErrors, err)
				}
			}
		}
	}

	return accumulatedErrors
}

func (dp *AzureDataProcessor) ProcessInstanceAndPolicy(policyPath string, instance map[string]any, activities []*proto.Activity) error {
	var accumulatedErrors error

	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  stringAddressed("reference"),
					Text: stringAddressed("The Continuous Compliance Framework"),
				},
			},
			Props: nil,
		},
		{
			Title: "Continuous Compliance Framework - Azure Postgres Database Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-azure-db-psql",
					Rel:  stringAddressed("reference"),
					Text: stringAddressed("The Continuous Compliance Framework' Azure Postgres Database Plugin"),
				},
			},
			Props: nil,
		},
	}
	components := []*proto.ComponentReference{
		{
			Identifier: "common-components/az-postgres-database",
		},
	}
	subjectAttributeMap := map[string]string{
		"type":        "azure",
		"service":     "postgres-database",
		"database_id": fmt.Sprintf("%v", instance["InstanceID"]),
	}

	subjects := []*proto.SubjectReference{
		{
			Type:       "az-postgres-database",
			Attributes: subjectAttributeMap,
			Title:      stringAddressed("Azure Postgres Database"),
			Remarks:    stringAddressed("Plugin running checks against Azure Postgres Database configuration"),
			Props: []*proto.Property{
				{
					Name:    "az-postgres-database",
					Value:   "CCF",
					Remarks: stringAddressed("The Azure Postgres Database server of which the policy was executed against"),
				},
			},
		},
	}

	dp.logger.Debug("evaluating instance with policy", "instanceID", instance["InstanceID"], "policyPath", policyPath)
	results, err := policyManager.New(dp.ctx, dp.logger, policyPath).Execute(dp.ctx, "compliance_plugin", instance)
	if err != nil {
		dp.logger.Error("policy evaluation failed", "error", err)
		return err
	}

	policyBundleSteps := make([]*proto.Step, 0)
	policyBundleSteps = append(policyBundleSteps, &proto.Step{
		Title:       "Compile policy bundle",
		Description: "Using a policy path, compile the policy files to an in memory executable.",
	})
	policyBundleSteps = append(policyBundleSteps, &proto.Step{
		Title:       "Execute policy bundle",
		Description: "Using an instance of a previously collected JSON-formatted Azure Postgres Database, execute the compiled policies",
	})

	activities = append(activities, &proto.Activity{
		Title:       "Execute policy",
		Description: "Prepare and compile policy bundles, and execute them using the prepared Azure Postgres Database configuration data",
		Steps:       policyBundleSteps,
	})

	for _, result := range results {
		observationUUIDMap := map[string]string{
			"policy":      result.Policy.Package.PurePackage(),
			"policy_file": result.Policy.File,
			"policy_path": policyPath,
		}
		maps.Copy(subjectAttributeMap, observationUUIDMap)
		observationUUID, err := sdk.SeededUUID(observationUUIDMap)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			// We've been unable to do much here, but let's try the next one regardless.
			continue
		}

		// Finding UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
		// This acts as an identifier to show the history of a finding.
		findingUUIDMap := map[string]string{
			"policy":      result.Policy.Package.PurePackage(),
			"policy_file": result.Policy.File,
			"policy_path": policyPath,
		}
		maps.Copy(subjectAttributeMap, findingUUIDMap)
		findingUUID, err := sdk.SeededUUID(findingUUIDMap)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			// We've been unable to do much here, but let's try the next one regardless.
			continue
		}

		observation := proto.Observation{
			ID:         uuid.New().String(),
			UUID:       observationUUID.String(),
			Collected:  timestamppb.New(dp.startTime),
			Expires:    timestamppb.New(dp.startTime.Add(24 * time.Hour)),
			Origins:    []*proto.Origin{{Actors: actors}},
			Subjects:   subjects,
			Activities: activities,
			Components: components,
			RelevantEvidence: []*proto.RelevantEvidence{
				{
					Description: fmt.Sprintf("Policy %v was executed against the Azure Postgres Database instance configuration, using the Azure Postgres Database Compliance Plugin", result.Policy.Package.PurePackage()),
				},
			},
		}

		newFinding := func() *proto.Finding {
			return &proto.Finding{
				ID:        uuid.New().String(),
				UUID:      findingUUID.String(),
				Collected: timestamppb.New(time.Now()),
				Labels: map[string]string{
					"type":          "azure",
					"service":       "postgres-database",
					"instance-id":   instance["InstanceID"].(string),
					"instance-name": instance["InstanceName"].(string),
					"_policy":       result.Policy.Package.PurePackage(),
					"_policy_path":  result.Policy.File,
				},
				Origins:             []*proto.Origin{{Actors: actors}},
				Subjects:            subjects,
				Components:          components,
				RelatedObservations: []*proto.RelatedObservation{{ObservationUUID: observation.ID}},
				Controls:            nil,
			}
		}

		observations := make([]*proto.Observation, 0)
		findings := make([]*proto.Finding, 0)

		if len(result.Violations) == 0 {
			observation.Title = stringAddressed(fmt.Sprintf("Plugin validation on %s passed.", result.Policy.Package.PurePackage()))
			observation.Description = fmt.Sprintf("Observed no violations on the %s policy on instance %s within the Azure Postgres Database Compliance Plugin.", result.Policy.Package.PurePackage(), instance["InstanceID"])

			observations = append(observations, &observation)

			finding := newFinding()
			finding.Title = fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())
			finding.Description = fmt.Sprintf("No violations found on the %s policy within the Azure Postgres Database Compliance Plugin.", result.Policy.Package.PurePackage())
			finding.Status = &proto.FindingStatus{
				State: runner.FindingTargetStatusSatisfied,
			}

			findings = append(findings, finding)
		} else {
			observation.Title = stringAddressed(fmt.Sprintf("The plugin found violations for policy %s.", result.Policy.Package.PurePackage()))
			observation.Description = fmt.Sprintf("Observed %d violation(s) on the %s policy and instance %s within the Azure Postgres Database Compliance Plugin.", len(result.Violations), instance["InstanceID"], result.Policy.Package.PurePackage())

			observations = append(observations, &observation)

			for _, violation := range result.Violations {
				finding := newFinding()
				finding.Title = violation.Title
				finding.Description = violation.Description
				finding.Remarks = stringAddressed(violation.Remarks)
				finding.Status = &proto.FindingStatus{
					State: runner.FindingTargetStatusNotSatisfied,
				}

				findings = append(findings, finding)
			}
		}

		err = dp.apiHelper.CreateObservations(dp.ctx, observations)
		if err != nil {
			dp.logger.Error("Failed to add observations", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}

		err = dp.apiHelper.CreateFindings(dp.ctx, findings)
		if err != nil {
			dp.logger.Error("Failed to add findings", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	return accumulatedErrors
}
