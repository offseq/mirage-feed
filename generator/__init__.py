"""Public generator for the OffSeq Mirage community feed."""

import uuid

NAME = "mirage-feed"
REPO = "offseq/mirage-feed"
BASE_URL = "https://feeds.offseq.com/mirage-feed"
MIRRORS = (
    "https://feeds.offseq.com/mirage-feed/",
    "https://raw.githubusercontent.com/offseq/mirage-feed/data/",
)
SCHEMA = "mirage-community/1"
SCHEMA_VERSION = "2.0"
PUBLISHER = "OffSeq"
LICENSE_DATA = "CC-BY-4.0"
LICENSE_CODE = "MIT"
TLP = "TLP:CLEAR"
NAMESPACE = uuid.UUID("5b0f4c8e-3a1d-5e7b-9c2f-6d4a8e1b7c30")
