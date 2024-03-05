import httpx
import backoff


def backoff_fatal_request_error(e):
    if not hasattr(e, "response") or not hasattr(e.response, "status_code"):
        # Errors which failed to get a response should retry.
        # Network failures, for example.
        return False
    if e.response.status_code == 429:
        return False
    return 400 <= e.response.status_code < 500


backoff_params = {
    "max_time": 300,
    "giveup": backoff_fatal_request_error,
    "jitter": backoff.full_jitter,
}


class Api:
    def __init__(
        self,
        token,
        v1_url="https://api.snyk.io/v1",
        rest_url="https://api.snyk.io/rest",
        rest_version="2023-07-19~beta",
    ):
        self.token = token
        self.v1_url = v1_url
        self.rest_url = rest_url
        self.rest_version = rest_version

    def v1_client(self):
        return httpx.Client(
            base_url=self.v1_url,
            headers={
                "Authorization": f"token {self.token}",
                "Content-Type": "application/json",
            },
            params={},
        )

    def v3_client(self):
        return httpx.Client(
            base_url=self.rest_url,
            headers={
                "Authorization": f"token {self.token}",
                "Content-Type": "application/vnd.api+json",
            },
            params={
                "version": self.rest_version,
            },
        )

    @backoff.on_exception(backoff.expo, httpx.HTTPError, **backoff_params)
    def org_projects(self, org_id: str):
        with self.v3_client() as c:
            next = f"/orgs/{org_id}/projects?expand=target&limit=100"
            while next:
                resp = c.get(next)
                resp.raise_for_status()
                assert resp.status_code == 200
                body = resp.json()

                projects = body.get("data", [])
                if len(projects) == 0:
                    return

                for project in body.get("data", []):
                    yield project

                next = body.get("links", {}).get("next")
            return

    @backoff.on_exception(backoff.expo, httpx.HTTPError, **backoff_params)
    def add_project_tag(self, org_id: str, project_id: str, tag: dict):
        with self.v1_client() as c:
            resp = c.post(
                f"/org/{org_id}/project/{project_id}/tags", json=tag, timeout=None
            )
            resp.raise_for_status()

    @backoff.on_exception(backoff.expo, httpx.HTTPError, **backoff_params)
    def remove_project_tag(self, org_id: str, project_id: str, tag: dict):
        with self.v1_client() as c:
            resp = c.post(
                f"/org/{org_id}/project/{project_id}/tags/remove",
                json=tag,
                timeout=None,
            )
            resp.raise_for_status()
