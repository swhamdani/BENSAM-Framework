class RiskScoring:

    def __init__(self):
        pass

    # ------------------------------------------------
    # Map CVSS score to base risk
    # ------------------------------------------------
    def cvss_weight(self, score):

        if score is None:
            return 0

        if score >= 9:
            return 40
        elif score >= 7:
            return 30
        elif score >= 4:
            return 20
        else:
            return 10


    # ------------------------------------------------
    # Port exposure risk
    # ------------------------------------------------
    def port_risk(self, services):

        if not services:
            return 0

        count = len(services)

        if count > 10:
            return 20
        elif count > 5:
            return 15
        elif count > 2:
            return 10
        else:
            return 5


    # ------------------------------------------------
    # Exploit availability risk
    # ------------------------------------------------
    def exploit_risk(self, vulns):

        risk = 0

        for v in vulns:
            if v.get("exploit_available"):
                risk += 20

        return min(risk, 30)


    # ------------------------------------------------
    # Calculate final risk score
    # ------------------------------------------------
    def calculate(self, host):

        score = 0

        services = host.get("services", [])
        vulns = host.get("vulnerability_intel", [])

        score += self.port_risk(services)

        for v in vulns:
            score += self.cvss_weight(v.get("cvss_score"))

        score += self.exploit_risk(vulns)

        return min(score, 100)


    # ------------------------------------------------
    # Convert score to severity level
    # ------------------------------------------------
    def classify(self, score):

        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "INFO"