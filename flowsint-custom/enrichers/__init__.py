"""
SPOTTER custom Flowsint enrichers.

These enrichers extend Flowsint's built-in enricher set with red-team-specific
processing logic.  They follow the Flowsint enricher module pattern defined in
flowsint-enrichers and can be registered via the Flowsint enricher template API.

To install, copy the three enricher files into flowsint-enrichers/ and rebuild,
or load them via the Flowsint enricher template upload endpoint.
"""

from .c2_session_enricher import C2SessionEnricher
from .process_tech_stack_enricher import ProcessTechStackEnricher
from .ad_permission_enricher import ADPermissionEnricher
from .flare_breach_enricher import FlareBreachEnricher
from .maigret_enricher import MaigretEnricher
from .credential_enricher import CredentialEnricher

__all__ = [
    "C2SessionEnricher",
    "ProcessTechStackEnricher",
    "ADPermissionEnricher",
    "FlareBreachEnricher",
    "MaigretEnricher",
    "CredentialEnricher",
]
