# Snyk Tags Tool

Snyk Tags is a CLI tool which can:

- Help filter Snyk projects by product type by adding product tags across a Snyk Group or Organization - using ```snyk-tags tag```
- Help filter Snyk projects by applying tags to a target import (for example a git repo like **snyk-labs/nodejs-goof**) - using ```snyk-tags target tag``` or from a csv/json file with ```snyk-tags fromfile target-tag```
- Help filter Snyk projects by applying attributes to a target import (for example a git repo like **snyk-labs/nodejs-goof**) - using ```snyk-tags target attributes``` or from a csv/json file with ```snyk-tags fromfile target-attributes```
- Help filter Snyk projects by adding the GitHub Code Owner as a tag to target import (must be a GitHub repo in the form **snyk-labs/nodejs-goof**) - using ```snyk-tags target github```
- Help with tag management by removing tags from a Group or a target import (for example a git repo like **snyk-labs/nodejs-goof**) - using ```snyk-tags target remove``` or listing all tags using ```snyk-tags list tags``` (also in bulk or from a csv/json file with ```snyk-tags fromfile```)

### snyk-tags tag

```snyk-tags tag``` is a CLI tool that uses the Snyk Project Tag API to assign tags in bulk to Snyk projects based on the product.

```snyk-tags tag``` will update all projects of the specified product within a Snyk Group or Organization with the product's tag.

You can also specify a custom tag for the specific project types.

[List all project types](#list-of-all-project-types)

### snyk-tags target

```snyk-tags target``` goes through a target (repo, container, CLI import) to assign tags, attributes and assign the GitHub code owner. Targets in snyk can be varied like:

- **snyk-labs/nodejs-goof** is the target from a git import
- **library/httpd** is the target from a container import
- **/snyk-labs/nodejs-goof** is the target from a CLI import

You can use:

- **```snyk-tags target tag```** to add tags to a target
- **```snyk-tags target attributes```** to add attributes to a target
- **```snyk-tags target github```** to add the GitHub Code Owner as a tag to a target. The GitHub repo must include the GitHub Organization e.g. **snyk-labs/nodejs-goof**

[List all possible attributes](#list-of-all-attributes)

### Viewing results

Once you run ```snyk-tags```, go into the UI, naviagate to the projects page and find the tags filter or attribute filter options on the left-hand menu. Select the tag/attribute you have applied and you will see all projects associated.

## Installation and requirements

### Requirements

Requires Python version above 3.6

### Installation

To install the simplest way is to use pip:

```bash
pip install snyk-tags
```

Alternatively you can clone the repo and then run the following commands:

```python
poetry install # To install dependencies
python -m snyk-tags # To run snyk-tags
```

## Examples

I want to filter all my Snyk Code projects to the whole Snyk Group:

``` bash
snyk-tags tag sast --group-id=abc --snyktkn=abc
```

I want to filter all my ```npm``` Snyk Open Source projects within a specific Snyk Organization:

``` bash
snyk-tags tag sca --scatype=npm --org-id=abc --snyktkn=abc
```

I want to filter all projects within my ```snyk-labs/nodejs-goof``` repo by ```project:snyk```

``` bash
snyk-tags target tag --target=snyk-labs/nodejs-goof --org-id=abc --snyktkn=abc --tagkey=project --tagvalue=snyk
```

I want to add attributes to all projects within my ```snyk-labs/python-goof``` repo. The attributes are ```critical, production, backend```

``` bash
snyk-tags target attributes  --target=snyk-labs/python-goof --org-id=abc --snytkn=abc --criticality=critical --environment=backend --lifecycle=production
```

I want mark with the repo owner all projects of the repo ```snyk-labs/nodejs-goof``` so I can filter by owner e.g.```Owner:EricFernandezSnyk```

``` bash
snyk-tags target github --target=snyk-labs/nodejs-goof --org-id=abc --snyktkn=abc --githubtkn=abc
```

I want to remove the tag project:snyk from the repo ```snyk-labs/nodejs-goof```

``` bash
snyk-tags remove tag-from-target --target=snyk-labs/nodejs-goof --group-id=abc --snyktkn=abc --tagkey=project --tagkey=snyk
```

I want to filter all projects within ```snyk-labs/nodejs-goof``` and ```snyk-labs/goof``` repo by ```project:snyk``` so I use a csv in the format ```org-id,target,key,value```

``` bash
snyk-tags fromfile target-tag --file=path/to/file.csv --snyktkn
```

## Types of projects and attributes

### List of all project types

|       Snyk IaC       | Snyk Open Source | Snyk Container | Snyk Code |
|:--------------------:|:----------------:|:--------------:|:---------:|
|    terraformconfig   |       maven      |   dockerfile   |    sast   |
|     terraformplan    |        npm       |       apk      |           |
|       k8sconfig      |       nuget      |       deb      |           |
|      helmconfig      |      gradle      |       rpm      |           |
| cloudformationconfig |        pip       |      linux     |           |
|       armconfig      |       yarn       |                |           |
|                      |     gomodules    |                |           |
|                      |     rubygems     |                |           |
|                      |     composer     |                |           |
|                      |        sbt       |                |           |
|                      |     golangdep    |                |           |
|                      |     cocoapods    |                |           |
|                      |      poetry      |                |           |
|                      |     govendor     |                |           |
|                      |        cpp       |                |           |
|                      |  yarn-workspace  |                |           |
|                      |        hex       |                |           |
|                      |       paket      |                |           |
|                      |      golang      |                |           |

### List of all attributes

| Criticality          | Environment | Lifecycle       |
|:--------------------:|:-----------:|:---------------:|
|       critical       |   frontend  |    production   |
|         high         |   backend   |   development   |
|        medium        |   internal  |     sandbox     |
|          low         |   external  |                 |
|                      |    mobile   |                 |
|                      |     saas    |                 |
|                      |    onprem   |                 |
|                      |    hosted   |                 |
|                      | distributed |                 |
