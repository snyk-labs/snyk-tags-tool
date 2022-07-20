# Snyk Tags Tool

Snyk Tags is a CLI tool with three purposes:

- Help filter Snyk projects by product type by adding product tags across a Snyk Group or Organization - using ```snyk-tags tag```
- Help filter Snyk projects by applying tags to a collection of projects (for example a git repo like **snyk-labs/nodejs-goof**) - using ```snyk-tags collection```
- Help filter Snyk projects by applying attributes to a collection of projects (for example a git repo like **snyk-labs/nodejs-goof**) - using ```snyk-tags attribute```

### snyk-tags tag

```snyk-tags tag``` is a CLI tool that uses the Snyk Project Tag API to assign tags in bulk to Snyk projects based on the product.

```snyk-tags tag``` will update all projects of the specified product within a Snyk Group or Organization with the product's tag.

You can also specify a custom tag for the specific project types.

### snyk-tags collection

```snyk-tags collection``` uses the Snyk Project Tag API to assign tags to all projects within a collection. A collection encompasses one or more projects in Snyk, for example:

- **snyk-labs/nodejs-goof** is a collection from a git import
- **library/httpd** is a collection from a container import
- **/snyk-labs/nodejs-goof** is a collection from a CLI import

[List all project types](#list-of-all-project-types)

### snyk-tags attribute

```snyk-tags attribute``` uses the Snyk Project Attribute API to assign attributes to all projects within a collection. A collection encompasses one or more projects in Snyk, for example:

- **snyk-labs/nodejs-goof** is a collection from a git import
- **library/httpd** is a collection from a container import
- **/snyk-labs/nodejs-goof** is a collection from a CLI import

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
snyk-tags tag sast --group-id=abc --token=abc
```

I want to filter all my ```npm``` Snyk Open Source projects within a specific Snyk Organization:

``` bash
snyk-tags tag sca --scatype=npm --org-id=abc --token=abc
```

I want to filter all projects within my ```snyk-labs/nodejs-goof``` repo by ```project:snyk```

``` bash
snyk-tags collection tag --collectionname=snyk-labs/nodejs-goof --org-id=abc --token=abc --tagkey=project --tagvalue=snyk
```

I want to add attributes to all projects within my ```snyk-labs/python-goof``` repo. The attributes are ```critical, production, backend```

``` bash
snyk-tags attribute collection  --collectionname=snyk-labs/python-goof --org-id=abc --token=abc --criticality=critical --environment=backend --lifecycle=production
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
