class AcmeHelperError(Exception):
    """Basisklasse für alle erwarteten Fehler."""


class ConfigError(AcmeHelperError):
    pass


class DnsError(AcmeHelperError):
    pass


class FortiWebError(AcmeHelperError):
    pass


class CertbotError(AcmeHelperError):
    pass
