class AcmeHelperError(Exception):
    """Basisklasse für alle erwarteten Fehler."""


class ConfigError(AcmeHelperError):
    pass


class DnsError(AcmeHelperError):
    pass


class FortiWebError(AcmeHelperError):
    def __init__(self, message: str, *, status: int | None = None, errcode: int | None = None):
        super().__init__(message)
        self.status = status
        self.errcode = errcode

    @property
    def not_found(self) -> bool:
        # FortiWeb 8.0.7 antwortet bei fehlenden Objekten mit HTTP 500 und errcode -3
        return self.status == 404 or self.errcode == -3 or "not found" in str(self).lower()


class CertbotError(AcmeHelperError):
    pass
