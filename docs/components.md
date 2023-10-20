
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
