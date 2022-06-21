# Snyk Tags Tool

CLI tool to assign tags to Snyk projects in bulk

"""
Need to install httpx and python-dotenv to run this script.

```
pip install httpx python-dotenv
```

Additionally, you will need a .env file with two variables in it:
GROUP_ID = (your group id)
AUTH_TOKEN = (your auth token)

Afterwards, use any Python version above 3.6, and run this script. 
It will update the Snyk Code projects in Snyk to have the sast tag.
Once this is run, go into the UI and click on the tags filter in the
projects page (left-hand menu). Select the type tag and sast as the key.
All of your Snyk Code projects will be shown via this filter.
"""