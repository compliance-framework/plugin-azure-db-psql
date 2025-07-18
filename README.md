
# Plugin Azure PostgreSQL Flexible Servers

## Configuration

> [!NOTE]
> Requires the typical Azure credentials to be set in your environment for the client to work. This can either be set manually or using the `az` tool

This plugin requires Azure credentials to be set in your environment for the client to work. You can set these manually or use the `az` CLI tool.

| Config Key         | Env Var                                 | Required | Description                                 |
|--------------------|-----------------------------------------|----------|---------------------------------------------|
| subscription_id    | $CCF_PLUGINS_<PLUGIN_NAME>_CONFIG_SUBSCRIPTION_ID | ✅       | Subscription ID for the Azure instance      |

## Building the plugin

```sh
mkdir -p dist
go build -o dist/plugin main.go
```

## Data structure passed to the policy manager

The plugin passes the raw structures provided by the Azure Go SDK for PostgreSQL Flexible Servers to the policy manager. These can be queried directly in Rego policies. The plugin also enriches the data with additional labels and context for compliance assessment.

The main Go type passed to the policy manager is: `armpostgresqlflexibleservers.Server`

For details on available fields, refer to the [Azure SDK documentation](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers#Server).

To see the data in action, review the unit tests in the [policies repo](https://github.com/compliance-framework/plugin-azure-db-psql-policies/tree/main/policies).

## Licence

[AGPL v3](./LICENSE)
