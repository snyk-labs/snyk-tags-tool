# Component tags

## What are component tags?

Component tags are used to describe how your software is composed, packaged and deployed, so that Snyk can relate security analysis findings to your cloud estate.

[Component tags](https://docs.snyk.io/manage-risk/insights/insights-setup/insights-setup-associating-snyk-open-source-code-and-container-projects) are used by [Snyk Insights](https://docs.snyk.io/manage-risk/insights) to associate related Snyk projects together, so that Snyk can provide contextual analysis of the actual risk when vulnerabilities are discovered in these software assets across the SDLC.

## How does `snyk-tags` help manage component tags?

For larger enterprise software estates, manually creating such tags, or even scripting them in CI/CD pipelines can be cumbersome and difficult to effectively govern at scale. When you have tens of thousands of SCM repositories and images, how do you manage all these definitions?

The `snyk-tags component` approach to managing this, is to use the naming conventions and structure which enterprises have already standardized on. With rules based on regular expressions, such conventions can usually be expressed declaratively and applied to bulk tag a large number of Snyk projects.

## How are component tag rules defined?

A `rules.yaml` file defines one or more _rules_. Each _rule_ matches one or more attributes of Snyk projects with exact values or a regular expression. _Named group captures_ in a regular expression can extract parts of these values into _variables_, which may be then referenced in a component tag expression which is evaluated and applied to the matching project.

### Working with fixed project attribute values

A very simple rule performs an exact match on the project name, and sets a fixed string value as the component tag:

```yaml
version: 1
rules:
- name: fixed-project-name-example
  projects:
    - name: my-example-project
  component: pkg:github/my-org/my-example-project@main
```

The component tag follows a [Package URL](https://github.com/package-url/purl-spec) (pURL) convention. Some assumptions encoded into this pURL:

- The software component is identified by a Github repo `my-example-project`, owned by organization `my-org`.
- The `main` branch of this repository was tested.

This component identifier is somewhat arbitrary, but a pURL is a useful reference to the component's source, and is also conventionally used in various SBOM formats.

### Regular expressions and variable capture

Imagine you have 10,000 projects in your Github org, all named similarly, but with different substrings in the repo name. To use the above "fixed value" type of rule, you'd need to define 10,000 such rules to assign a component tag to each.

Tagging such projects with a regular expression rule looks like this:

```yaml
version: 1
rules:
- name: regex-project-name-example
  projects:
    - name:
        regex: '^my-org/(?P<project>\w+):'
  component: pkg:github/my-org/{project}@main
```

A few observations about this rule worth highlighting:

- The project `name` can either be a fixed string, or an object with a `regex` attribute, which defines a regular expression match and capture for the attribute.
- The regular expression is matching all project names that start with `my-org/`.
- The word following `my-org/` (`\w+` matches one or more alphanumeric characters) is captured to a variable named `project` (that's what the `?P<project>` does in the parenthesized group).
- The captured `project` variable is used in the component tag expression.

### Normalizing over multiple project naming conventions

Unfortunately Snyk doesn't always name projects the same way. There are several reasons for this, but generally it's because projects (the subject of a Snyk test) are identified differently depending on what kind of test is being run. Snyk Container project names, for example, can reference an OCI image repository location, while Snyk Open Source and Snyk Code will generally reference source code repository locations.

We can define multiple project pattern matchers within the same rule to normalize over these differences. Again, this is how we teach Snyk Insights "the subjects of these tests are all part of the same 'software component'".

```yaml
version: 1
rules:
- name: regex-multiple-snyk-projects
  projects:
    - name:
        regex: '^my-org/(?P<project>\w+):'
    - name:
        regex: '^(?P<project>\w+):'
      origin: ecr
  component: pkg:github/my-org/{project}@main
```

Comparing with the previous example, we've added an additional project matcher. This matcher:

- Extracts the first alphanumeric string from the name preceding a `:` as the `project` variable...
- ...but only when the project `origin` is `ecr`.

Projects with `origin: ecr` indicate a container in an [Amazon Elastic Container Registry (ECR)](https://docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html) was tested with Snyk Container.

Project matchers are evaluated on each project in the same order in which they are defined in the rule, until there is a match. The variables extracted from the match are used in the `component` expression to tag the project. If there is no match, the project is not tagged.

Note that the same variables must be captured in each matcher, in order to reference them in the `component` tag expression.

### Project attributes available for matching

The following project attributes may be used in a project matcher:

- `name`
- `origin`
- `target.display_name`
- `target.url`
- `target_reference`

For best results when developing rules, explore the values of these attributes in your projects with the [Snyk REST API](https://apidocs.snyk.io).

Matchers operate on objects which are simplified from Projects API responses. Only these fields are supported -- though note that not all projects set all of these fields. The matcher fields are shown below in YAML format, with commentary relating each to Projects REST API resources.

```
projects:
- name: '...'             # from data.attributes.name
  origin: '...'           # from data.attributes.origin
  target:
    display_name: '...'   # from relationships.target.data.attributes.display_name
    url: '...'            # from relationships.target.data.attributes.url
  target_reference: '...' # from data.attributes.target_reference
```

#### Target attributes

`target` sub-attributes are defined as a sub-object of the project. `target.url` for example, can be used in a rule like this:

```yaml
version: 1
rules:
- name: target-url-example
  projects:
    - target:
        url:
          regex: 'http(s)?://github.com/my-org/(?P<project>\w+).git'
  component: pkg:github/my-org/{project}@main
```

# Complete rules file example with commentary

A `rules.yaml` can contain multiple rules. These are evaluated by `snyk-tags component` in the same order they are defined, on each project in a Snyk org. The first rule that matches a project is used to tag that project.

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

## `snyk-tags component` command-line usage

I want to add `component` tags on projects in my Snyk Organization for [Snyk Insights](https://docs.snyk.io/manage-issues/insights/insights-setup/insights-setup-associating-snyk-open-source-code-and-container-projects), based on rules which match and extract certain features of project and attributes.

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
