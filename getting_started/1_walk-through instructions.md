
## Prepare the Microsoft Fabric environment

### 1. Upload the yaml config file to a Fabric Lakehouse

As we created the yaml configuration file in the prerequisite step stored locally, we will upload it to Fabric and run it in a Notebook. You can either use an existing Fabric Lakehouse or create a new Lakehouse. Instructions to do so can be found [here](https://learn.microsoft.com/en-us/fabric/data-engineering/create-lakehouse).

In your Lakehouse, at the top you will find "Get Data" to upload files and choose the yaml configuration file you have created in step 0_prerequisites. Ensure the yaml file is stored in your Lakehouse: Refresh the Lakheouse and  cnavigate to the Lakehouse file section to find your yaml file.


### 2. Create a Notebook to run Policy Weaver

You can stay in the Fabric Lakehouse and click at the top bar to create a new Notebook. You can also run the PolicyWeaver commands with a different tool.

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