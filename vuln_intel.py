import vulners

class VulnerabilityIntel:

    def __init__(self, api_key):
        self.client = vulners.Vulners(api_key=api_key)

    def enrich_cve(self, cve_id):

        try:
            result = self.client.document(cve_id)

            if not result:
                return None

            data = result.get("_source", {})

            return {
                "cve": cve_id,
                "cvss_score": data.get("cvss", {}).get("score"),
                "severity": data.get("cvss", {}).get("severity"),
                "description": data.get("description"),
                "exploit_available": data.get("exploit", False),
                "references": data.get("references", [])
            }

        except Exception:
            return None