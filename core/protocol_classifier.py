# src/core/protocol_classifier.py

"""
Protocol classifier: identifies protocol from contract metadata, using signatures, names, keywords.
"""

import logging
from typing import Optional
from .parser import ParsedContract
from .domain_classifier import DomainClassifier, ClassificationResult

logger = logging.getLogger(__name__)

class ProtocolClassifier:
    """
    Helper wrapper over DomainClassifier to return only the protocol (extracted early).
    """
    def __init__(self):
        self.domain_classifier = DomainClassifier()

    def classify_protocol(self, parsed_contract: ParsedContract) -> Optional[str]:
        try:
            result: ClassificationResult = self.domain_classifier.classify(parsed_contract)
            if result.protocol:
                logger.info(f"ProtocolClassifier: identified protocol = {result.protocol.value}")
                return result.protocol.value
            logger.warning("ProtocolClassifier: no protocol match")
            return None
        except Exception as e:
            logger.error(f"Protocol classification error: {str(e)}")
            return None
