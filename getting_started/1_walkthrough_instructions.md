
## Prepare the Microsoft Fabric environment

### 1. Create a Shortcut in your Lakehouse to the Mirrored Databricks tables

Log in to Microsoft Fabric and navigate to the Lakehouse you created in step 0_preprequisites. Under the Tab "Get Data" select to create a shortcut and choose "Microsoft OneLake" from the internal sources section. In the overview that is shown next, select the Mirrored Azure Databricks catalog item in which you have connected your Azure Databricks tables to. 


### 2. Upload the yaml config file to your Lakehouse

Again under "Get Data", select to upload files and choose the yaml configuration file you have created in step 0_prerequisites. Ensure the yaml file is stored in your Lakehouse: Click on the left side of the Lakehouse navigation to the file section and find your yaml file.


### 3. Create a Notebook to run Policy Weaver

You can stay in the Fabric Lakehouse and click to create a new Notebook at the top bar or choose to run the PolicyWeaver with a different tool.

Using the Notebook in Fabric, paste the following code:

```python
%pip install policy-weaver --quiet
``` 

```python
#import the PolicyWeaver library
from policyweaver.weaver import WeaverAgent
from policyweaver.plugins.databricks.model import DatabricksSourceMap

#Load config
config = DatabricksSourceMap.from_yaml("path_to_your_config.yaml")

#run the PolicyWeaver
await WeaverAgent.run(config)
```