# Snyk Tags Tool

Snyk Tags is a CLI tool with two purposes:

- Help filter Snyk projects by product type by adding product tags across a Snyk Group or Organization - using ```snyk-tags tag```
- Help filter Snyk projects by applying tags to a collection of projects (for example a git repo like **snyk-labs/nodejs-goof**) - using ```snyk-tags collection```

### snyk-tags tag

```snyk-tags tag``` is a CLI tool that uses the Snyk Project API to assign tags in bulk to Snyk projects based on the product type.

```snyk-tags tag``` will update all projects of the specified product type within a Snyk Group or Organization with the product's tag.

You can also specify a custom tag for the products.

### snyk-tags collection

```snyk-tags collection``` uses the Snyk Project API to assign tags to all projects within a collection. A collection encompasses one or more projects in Snyk, for example:

- **snyk-labs/nodejs-goof** is a collection from a git import
- **library/httpd** is a collection from a container import
- **/snyk-labs/nodejs-goof** is a collection from a CLI import

Once you run ```snyk-tags```, go into the UI, naviagate to the projects page and find the tags filter options on the left-hand menu. Select the tag you have applied and you will visualize all projects associated.

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

I want to filter all projects within my ```snyk-labs/nodejs-goof``` repo as ```project:snyk```

``` bash
snyk-tags collection apply --collectionname=snyk-labs/nodejs-goof --org-id=abc --token=abc --tagkey=project --tagvalue=snyk
```
