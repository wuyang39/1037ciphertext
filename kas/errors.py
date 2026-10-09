"""KAS failures mapped to explicit policy decisions."""


class KASError(Exception):
    """Base class for expected KAS rejections."""


class ChallengeNotFound(KASError):
    """The challenge does not exist or was already consumed."""


class ChallengeExpired(KASError):
    """The challenge exceeded its short validity window."""


class AttestationRejected(KASError):
    """Quote verification or REPORTDATA binding failed."""


class PolicyRejected(KASError):
    """The quote does not satisfy the registered release policy."""
