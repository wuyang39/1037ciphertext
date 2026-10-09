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


class TicketNotFound(KASError):
    """The requested JobTicket does not exist."""


class TicketExpired(KASError):
    """The JobTicket has exceeded its validity window."""


class TicketAlreadyConsumed(KASError):
    """The one-use JobTicket was consumed previously."""


class TicketBindingRejected(KASError):
    """The ticket signature or request binding is invalid."""


class LeaseRejected(KASError):
    """The enclave Lease is missing, expired, or bound to another node."""


class StorageKeyRejected(KASError):
    """A storage-key release request failed policy or replay checks."""
