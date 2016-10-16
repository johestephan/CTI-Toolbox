# CTI-Toolbox
Cyber Threat Intelligence - Toolbox

In order to run, you need to create "iprep_conf.py" in the following format

```
# Basic configuration file

#Alienvault OTX
otx_authkey = ""

#XForce exchange
xfex_cred = ""

# Settings for Web-frontend
LOCAL_IP = "127.0.0.1"
LOCAL_PORT = "5010"

VERSION = "1.0.0 (BETA_1)"
```
For the needed credentials please sign up at
* [IBM XForce Exchange](https://exchange.xforce.ibmcloud.com/)
* [Alienvault Open Threat Exchange](https://otx.alienvault.com/api/)

```
Copyright 2016 Joerg Stephan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```