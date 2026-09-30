"""
SPOTTER custom Flowsint types.

These Pydantic models represent red-team-specific entity types that extend
Flowsint's built-in type system.  They are used:
  - As documentation / schema reference for n8n workflow Code nodes
  - By the custom enrichers in flowsint-custom/enrichers/
  - When constructing node payloads for the Flowsint import/execute API

To register these types in a live Flowsint instance, POST each model's
schema to  POST /api/custom-types  using the Flowsint API.
"""

from .c2_session import C2Session, SESSION_NOUN
from .file_share import FileShare
from .ad_permission import ADPermission
from .flare_breach import FlareBreach
from .social_profile import SocialProfile, derive_specialty
from .cert_template import CertTemplate
from .enterprise_ca import EnterpriseCA
from .gpo import GPO
from .ad_risk import ADRisk
from .vulnerability import Vulnerability
from .company import Company, RELATIONSHIPS as COMPANY_RELATIONSHIPS, vendor_from_hostname

__all__ = [
    # C2Session replaced the framework-specific CobaltBeacon type; live graphs
    # predating the change need scripts/migrate_c2session.py.
    "C2Session", "SESSION_NOUN", "FileShare", "ADPermission", "FlareBreach",
    "SocialProfile", "derive_specialty",
    # AD attack-path node types (Kerberos / ADCS / GPO tradecraft)
    "CertTemplate", "EnterpriseCA", "GPO",
    # AD configuration findings (PingCastle health check) — register with
    # scripts/register_pingcastle_type.py before ingesting.
    "ADRisk",
    # Scanner findings (Nessus CSV export) — register with
    # scripts/register_nessus_type.py before ingesting.
    "Vulnerability",
    # Real-world commercial entities (WF13 `org` source). Deliberately NOT the
    # built-in `organization` label, which SharpHound already uses for AD groups,
    # domains and OUs — see company.py. Register with
    # scripts/register_company_type.py before running the org source.
    "Company", "COMPANY_RELATIONSHIPS", "vendor_from_hostname",
]
