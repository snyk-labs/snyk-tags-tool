# Snyk Tags Tool

![snyk-oss-category](https://github.com/snyk-labs/oss-images/blob/main/oss-community.jpg)

#### **Snyk Tags is a CLI tool which can:**

- Help filter Snyk projects by product type by adding product tags across a Snyk Group or Organization - using ```snyk-tags tag```
- Help filter Snyk projects by applying tags to all projects containing a specific name ```snyk-tags tag alltargets --contains-name=```
- Help filter Snyk projects by applying tags to a target import (for example a git repo like **snyk-labs/nodejs-goof**) - using ```snyk-tags target tag``` or from a csv/json file with ```snyk-tags fromfile target-tag```
- Help filter Snyk projects by applying attributes to a target import (for example a git repo like **snyk-labs/nodejs-goof**) - using ```snyk-tags target attributes``` or from a csv/json file with ```snyk-tags fromfile target-attributes```
- Help filter Snyk projects by adding the GitHub CODEOWNERS (only GitHub handles) as tags to the target import (must be a GitHub repo in the form **snyk-labs/nodejs-goof**) - using ```snyk-tags target github owners```
- Help with tag management by removing tags from a Group or a target import (for example a git repo like **snyk-labs/nodejs-goof**) - using ```snyk-tags target remove``` or listing all tags using ```snyk-tags list tags``` (also in bulk or from a csv/json file with ```snyk-tags fromfile```)

### **snyk-tags tag**

```snyk-tags tag``` is a CLI tool that uses the Snyk Project Tag API to assign tags in bulk to Snyk projects based on the product.

```snyk-tags tag``` will update all projects of the specified product within a Snyk Group or Organization with the product's tag.

You can also specify a custom tag for the specific project types.

[List all project types](#list-of-all-project-types)

### **snyk-tags target**

```snyk-tags target``` goes through a target (repo, container, CLI import) to assign tags, attributes and assign GitHub metadata. Targets in snyk can be varied like:

- **snyk-labs/nodejs-goof** is the target from a git import
- **library/httpd** is the target from a container import
- **/snyk-labs/nodejs-goof** is the target from a CLI import

You can use:

- **```snyk-tags target tag```** to add tags to a target
- **```snyk-tags target attributes```** to add attributes to a target
- **```snyk-tags target github```** for specific GitHub metadata. The GitHub repo must include the GitHub Organization e.g. **snyk-labs/nodejs-goof**

[List all possible attributes](#list-of-all-attributes)

#### **snyk-tags target github**

To import GitHub metadata such as CODEOWNERS or Topics, you can use this command.

**Requirements:**

- GitHub PAT with ```read:org``` permissions

**Usage:**

- **```snyk-tags target github owners```** to add the CODEOWNERS file information as tags (limited to GitHub handles for now)
- **```snyk-tags target github topics```** to add the GitHub Topics as tags

### **Viewing results**

Once you run ```snyk-tags```, go into the UI, naviagate to the projects page and find the tags filter or attribute filter options on the left-hand menu. Select the tag/attribute you have applied and you will see all projects associated.

## **Installation and requirements**

### **Requirements**

Requires Python version above 3.6

### **Installation**

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

For the following examples you will need a Snyk API token, this can either be a personal Snyk Group/Org admin or a service account, [here](https://docs.snyk.io/snyk-api-info/authentication-for-api) is more information on how to generate a Snyk API token. You can then pass this token as part of the command through ```--snyktkn=abc``` or as an environment variable ```SNYK_TOKEN```

### Applying tags by Snyk product

I want to filter all my Snyk Code projects to the whole Snyk Group:

``` bash
snyk-tags tag sast --group-id=abc --snyktkn=abc
```

I want to filter all my ```npm``` Snyk Open Source projects within a specific Snyk Organization:

``` bash
snyk-tags tag sca --scatype=npm --org-id=abc --snyktkn=abc
```

### Applying tags based on project name

I want to filter all my Snyk projects sharing a common project name substring

``` bash
snyk-tags tag alltargets --contains-name=microservice --group-id=abc --org-id=abc --snyktkn=abc --tagkey=app --tagvalue=microservice
```

### Managing tags based on target SCM repository

I want to filter all projects within my ```snyk-labs/nodejs-goof``` repo by ```project:snyk```

``` bash
snyk-tags target tag --target=snyk-labs/nodejs-goof --org-id=abc --snyktkn=abc --tagkey=project --tagvalue=snyk
```

I want to add attributes to all projects within my ```snyk-labs/python-goof``` repo. The attributes are ```critical, production, backend```

``` bash
snyk-tags target attributes  --target=snyk-labs/python-goof --org-id=abc --snytkn=abc --criticality=critical --environment=backend --lifecycle=production
```

I want mark with the repo owners all projects of the repo ```snyk-labs/nodejs-goof``` so I can filter by owner e.g.```Owner:EricFernandezSnyk```

``` bash
snyk-tags target github owners --target=snyk-labs/nodejs-goof --org-id=abc --snyktkn=abc --githubtkn=abc
```

I want add my GitHub Topics to all projects of the repo ```snyk-labs/nodejs-goof``` so I can filter by topics e.g.```GitHubTopic:python3```

``` bash
snyk-tags target github topics --target=snyk-labs/nodejs-goof --org-id=abc --snyktkn=abc --githubtkn=abc
```

I want to remove the tag project:snyk from the repo ```snyk-labs/nodejs-goof```

``` bash
snyk-tags remove tag-from-target --target=snyk-labs/nodejs-goof --group-id=abc --snyktkn=abc --tagkey=project --tagkey=snyk
```

I want to remove the tag app:microservice from all targets within a specific Snyk Organization

``` bash
snyk-tags remove tag-from-alltargets --contains-name=apps-demo --org-id=abc --tagkey=app --tagvalue=microservice
```

I want to filter all projects within ```snyk-labs/nodejs-goof``` and ```snyk-labs/goof``` repo by ```project:snyk``` so I use a csv in the format ```org-id,target,key,value```

``` bash
snyk-tags fromfile target-tag --file=path/to/file.csv --snyktkn
```

### Defining software component tags for Snyk Insights

I want to add `component` tags on projects in my Snyk Organization for [Snyk Insights](https://docs.snyk.io/manage-issues/insights/insights-setup/insights-setup-associating-snyk-open-source-code-and-container-projects), based on rules which match and extract certain features of project and attributes. See section on [Component Tags](#component-tags-for-snyk-insights) below.

```bash
snyk-tags component tag --org-id=abc rules.yaml
```

I want to preview component tag processing changes before applying them.

```bash
snyk-tags component tag --dry-run rules.yaml
```

I want to remove all component tags, as determined by the same rules.

```bash
snyk-tags component tag --remove rules.yaml
```

I want to replace _all_ component tags that might exist on matching projects with only those specified by the rules.

```bash
snyk-tags component tag --exclusive rules.yaml
```

I want to remove _all_ component tags from matching projects.

```bash
snyk-tags component tag --remove --exclusive rules.yaml
```

#### Formatting options

I want to store a CSV report of component tag rule processing to a file.

```bash
snyk-tags component tag --format csv rules.yaml | tee component-tags.csv
```

I want to append a newline-delimited JSON (ndjson) log of component tag processing to a file.

```bash
snyk-tags component tag --format json rules.yaml | tee -a component-tags.ndjson
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

## Component tags for Snyk Insights

Part of the setup process for Snyk Insights involves associating Snyk Open Source, Code and Container projects together. For a large organization this can be a daunting task. The `snyk-tags component tag` command allows automating the application of such tags based on regular expression matching and extraction.

This tool may be run up-front as part of onboarding, but also as a regular batch job. This allows component tags to be more centrally managed across an organization.

### Component rules

The format for the rules file is as follows:

```yaml
# 'version' is the version of this rules file format, currently 1
version: 1

# 'rules' is an array of rule objects.
# Rule objects are evaluated against each project in the specified --org-id
# The first rule that matches is used to tag the project with its component: tag.
# Rules are applied in the order in which they appear in this file.
rules:

  # A rule which normalizes component names across different types of projects.
  # If you inspect the contents of Snyk projects, you'll find that different
  # origins contain different identifiers and in different formats.
  - name: my-retail-store

    # 'projects' is a list of project matchers. Just like the rules, these are
    # applied in the order in which they are defined here, the first one that
    # matches is used to extract variables used in the component expression
    # below.
    projects:

      # A project matcher which evaluates a regular expression against the
      # project's 'name' attribute. If it matches, the named capture group
      # "service_name" is stored as a variable.
      - name:
          regex: '^my-retail-store/(?P<service_name>\w+):'
        # This matcher only applies to projects from Snyk's Github integration
        origin: github

      # A project matcher which extracts service_name from a container image
      # project.
      - name:
          regex: '^(?P<service_name>\w+):'
        origin: ecr

      # A project matcher which matches and extracts from the target
      # relationship.
      - target:
          url:
            regex: 'http://github.com/my-retail-store/(?P<service_name>\w+)\.git'
        origin: cli

    # Define the component tag for all matching projects. Snyk recommends a
    # Package URL (pURL) format beginning with `pkg:` for use with Insights.
    # Named capture values extracted in the matchers above may be interpolated
    # here as variables, using Python's fstring formatting convention.
    #
    # Note that if a variable is used, the named capture must be present in all
    # project matchers defined above.
    component: 'pkg:github/my-retail-store/{service_name}@main'
```

Matchers operate on objects which are simplified from Projects API responses. Only these fields are supported -- though note that not all projects set all of these fields. The fields are shown below in YAML format, commented with their mapping from Projects REST API resources.

```
- name: '...'             # from data.attributes.name
  origin: '...'           # from data.attributes.origin
  target:
    display_name: '...'   # from relationships.target.data.attributes.display_name
    url: '...'            # from relationships.target.data.attributes.url
  target_reference: '...' # from data.attributes.target_reference
```
