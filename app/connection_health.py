"""Do not mistake one transient probe failure for a sustained outage."""
class ConnectionHealth:
    def __init__(self, threshold=3):
        self.threshold=threshold
        self.failures=0
        self.healthy=None

    def observe(self, success):
        self.failures=0 if success else self.failures+1
        if success:self.healthy=True
        elif self.failures>=self.threshold:self.healthy=False
        return {'vpn_ok':self.healthy,'degraded':not success,
                'consecutive_failures':self.failures}
