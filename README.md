# Policy Weaver 

## Overview

[Microsoft Fabric Mirroring](https://learn.microsoft.com/en-us/fabric/database/mirrored-database/overview) is a managed, friction-free way of synchronizing data from a diverse set of data & analytic platforms to Fabric via OneLake. The data in proprietary formats are being automatically transformed in a queryable format (Delta Parquet) in OneLake in near real-time (using the data sources CDC capabilities) withouth the need to setting up the transformation jobs. With Mirroring, the data is kept in sync between source system and Fabric Onelake, enabling further use of the delta parquet tables with all Fabric workloads.

While Fabric Mirroring provides all the capabilities required to automatically keep data in sync, data access policies defined by the source system are out-of-scope and must be handled manually when the relicated delta parquet tables in Fabric are being used. Manually handling of these data access policies presents a challenge for ensuring consistent security across the data estate while reducing risks or vulnerabilities associated with out-of-sync security policies.

**The Policy Weaver project** addresses these challenges by automating the synchronzation of data access policies from source to Fabric in a transparent and auditable mmaner. It is made available as a Python library and can be run either within Fabric with a Notebook or from anywhere with a Python runtime.

Designed as a pluggable framework, **Policy Weaver** provides connectors that handle the export of access policies from a configured source before applying them to the mirror data within Fabric.

Policy Weaver will initially supports the following sources:
- [Azure Databricks Unity Catalog]()
- BigQuery
- Snowflake


> <b>Note:</b> Policy Weaver is limited to read-only policies for now. Support 
> for row filter and column-masking policies will be added in a future version.


For more information on prerequisites and instructions on getting started, please see the [Getting Started]() documentation. 

## OneLake Data Access Roles Overview

**Policy Weaver** uses [OneLake Data Access Roles](https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-data-access-roles), currently in public preview, to coalesce source system security policies into access policies that apply uniformly across the Fabric platform. With Data Access Roles, security policies are defined as role-based access controls (RBAC) on the data stored in OneLake.

When data is accessed from anywhere within Fabric, the defined RBAC policies are enforced. This means that data whether is accessed from a Fabric Notebook, SQL Endpoint or Semantic model the security policies defined by the source system are enforced consistently as expected.

For more details on OneLake Security concepts and how OneLake Access roles relate, please see official Microsoft documentation: [OneLake Security Overview](https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-security) 


## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.