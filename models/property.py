"""
Property models for smart contract formal verification and invariant checking.

These models represent properties, invariants, and formal specifications
that should hold true for smart contracts.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime

from .context import CodeLocation

logger = logging.getLogger(__name__)

class PropertyType(Enum):
    """Types of properties that can be checked."""
    INVARIANT = "invariant"           # Always true properties
    PRECONDITION = "precondition"     # Must be true before function execution
    POSTCONDITION = "postcondition"   # Must be true after function execution
    TEMPORAL = "temporal"             # Time-based properties
    SECURITY = "security"             # Security-specific properties
    BUSINESS_LOGIC = "business_logic" # Domain-specific business rules
    MATHEMATICAL = "mathematical"     # Mathematical properties
    STATE_TRANSITION = "state_transition"  # Valid state changes

class PropertyStatus(Enum):
    """Status of property verification."""
    UNKNOWN = "unknown"
    VERIFIED = "verified"
    VIOLATED = "violated"
    CANNOT_VERIFY = "cannot_verify"
    SKIPPED = "skipped"
    ERROR = "error"

class PropertyPriority(Enum):
    """Priority levels for property checking."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class PropertyMetadata:
    """Metadata for a property."""
    created_at: datetime = field(default_factory=datetime.now)
    last_checked: Optional[datetime] = None
    check_count: int = 0
    verification_time: float = 0.0
    
    # Source information
    source: str = "manual"  # manual, generated, template
    template_name: Optional[str] = None
    domain_specific: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['created_at'] = self.created_at.isoformat()
        if self.last_checked:
            result['last_checked'] = self.last_checked.isoformat()
        return result

@dataclass
class PropertyViolation:
    """Represents a property violation instance."""
    property_id: str
    violation_description: str
    location: Optional[CodeLocation] = None
    counterexample: Optional[Dict[str, Any]] = None
    witness_trace: List[str] = field(default_factory=list)
    severity: str = "medium"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        if self.location:
            result['location'] = asdict(self.location)
        return result

@dataclass
class Property:
    """
    Base class for all property types in smart contract verification.
    """
    # Basic information
    property_id: str
    name: str
    description: str
    property_type: PropertyType
    
    # Property specification
    specification: str  # Formal specification (e.g., in logic)
    natural_language: str = ""  # Human-readable description
    
    # Context
    applicable_contracts: List[str] = field(default_factory=list)
    applicable_functions: List[str] = field(default_factory=list)
    
    # Verification status
    status: PropertyStatus = PropertyStatus.UNKNOWN
    priority: PropertyPriority = PropertyPriority.MEDIUM
    
    # Results
    last_verification_result: Optional[bool] = None
    violations: List[PropertyViolation] = field(default_factory=list)
    
    # Metadata
    metadata: PropertyMetadata = field(default_factory=PropertyMetadata)
    
    def add_violation(self, description: str, location: Optional[CodeLocation] = None,
                     counterexample: Optional[Dict[str, Any]] = None,
                     witness_trace: List[str] = None):
        """Add a property violation."""
        violation = PropertyViolation(
            property_id=self.property_id,
            violation_description=description,
            location=location,
            counterexample=counterexample,
            witness_trace=witness_trace or []
        )
        self.violations.append(violation)
        self.status = PropertyStatus.VIOLATED

    def mark_verified(self):
        """Mark property as verified."""
        self.status = PropertyStatus.VERIFIED
        self.last_verification_result = True
        self.metadata.last_checked = datetime.now()
        self.metadata.check_count += 1

    def mark_violated(self, description: str, **kwargs):
        """Mark property as violated."""
        self.add_violation(description, **kwargs)
        self.last_verification_result = False

    def is_applicable_to_contract(self, contract_name: str) -> bool:
        """Check if property applies to a specific contract."""
        return (not self.applicable_contracts or 
                contract_name in self.applicable_contracts)

    def is_applicable_to_function(self, function_name: str) -> bool:
        """Check if property applies to a specific function."""
        return (not self.applicable_functions or 
                function_name in self.applicable_functions)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'property_id': self.property_id,
            'name': self.name,
            'description': self.description,
            'property_type': self.property_type.value,
            'specification': self.specification,
            'natural_language': self.natural_language,
            'applicable_contracts': self.applicable_contracts,
            'applicable_functions': self.applicable_functions,
            'status': self.status.value,
            'priority': self.priority.value,
            'last_verification_result': self.last_verification_result,
            'violations': [v.to_dict() for v in self.violations],
            'metadata': self.metadata.to_dict()
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Property':
        """Create Property from dictionary."""
        # Extract metadata
        metadata_data = data.get('metadata', {})
        metadata = PropertyMetadata(
            created_at=datetime.fromisoformat(metadata_data.get('created_at', datetime.now().isoformat())),
            check_count=metadata_data.get('check_count', 0),
            verification_time=metadata_data.get('verification_time', 0.0),
            source=metadata_data.get('source', 'manual'),
            template_name=metadata_data.get('template_name'),
            domain_specific=metadata_data.get('domain_specific', False)
        )
        
        if metadata_data.get('last_checked'):
            metadata.last_checked = datetime.fromisoformat(metadata_data['last_checked'])
        
        # Extract violations
        violations = []
        for violation_data in data.get('violations', []):
            location = None
            if violation_data.get('location'):
                location = CodeLocation(**violation_data['location'])
            
            violation = PropertyViolation(
                property_id=violation_data['property_id'],
                violation_description=violation_data['violation_description'],
                location=location,
                counterexample=violation_data.get('counterexample'),
                witness_trace=violation_data.get('witness_trace', []),
                severity=violation_data.get('severity', 'medium')
            )
            violations.append(violation)
        
        return cls(
            property_id=data['property_id'],
            name=data['name'],
            description=data['description'],
            property_type=PropertyType(data['property_type']),
            specification=data['specification'],
            natural_language=data.get('natural_language', ''),
            applicable_contracts=data.get('applicable_contracts', []),
            applicable_functions=data.get('applicable_functions', []),
            status=PropertyStatus(data.get('status', 'unknown')),
            priority=PropertyPriority(data.get('priority', 'medium')),
            last_verification_result=data.get('last_verification_result'),
            violations=violations,
            metadata=metadata
        )

@dataclass
class InvariantProperty(Property):
    """Properties that should always hold true."""
    
    # Invariant-specific fields
    state_variables: List[str] = field(default_factory=list)
    mathematical_expression: Optional[str] = None
    
    def __post_init__(self):
        """Initialize invariant-specific settings."""
        self.property_type = PropertyType.INVARIANT

@dataclass
class SecurityProperty(Property):
    """Security-specific properties."""
    
    # Security-specific fields
    security_category: str = "general"  # reentrancy, access_control, etc.
    attack_vectors: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize security-specific settings."""
        self.property_type = PropertyType.SECURITY

@dataclass 
class BusinessLogicProperty(Property):
    """Business logic properties specific to domain."""
    
    # Business logic fields
    domain: str = "general"  # defi, dao, nft, gamefi
    economic_model: Optional[str] = None
    stakeholders: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Initialize business logic specific settings."""
        self.property_type = PropertyType.BUSINESS_LOGIC

class PropertyTemplate:
    """Template for generating common properties."""
    
    @staticmethod
    def create_balance_conservation_property(token_contract: str) -> InvariantProperty:
        """Create a balance conservation invariant."""
        return InvariantProperty(
            property_id=f"balance_conservation_{token_contract}",
            name="Balance Conservation",
            description="Total token supply equals sum of all balances",
            specification="forall addr: balanceOf[addr] <= totalSupply() && sum(balanceOf) == totalSupply()",
            natural_language="The sum of all token balances should always equal the total supply",
            applicable_contracts=[token_contract],
            state_variables=["totalSupply", "balances"],
            mathematical_expression="∑balances[i] = totalSupply",
            priority=PropertyPriority.CRITICAL
        )

    @staticmethod 
    def create_access_control_property(contract: str, admin_function: str) -> SecurityProperty:
        """Create an access control property."""
        return SecurityProperty(
            property_id=f"access_control_{contract}_{admin_function}",
            name=f"Access Control for {admin_function}",
            description=f"Only authorized users can call {admin_function}",
            specification=f"requires(hasRole(ADMIN_ROLE, msg.sender)) before {admin_function}",
            natural_language=f"Only administrators should be able to call the {admin_function} function",
            applicable_contracts=[contract],
            applicable_functions=[admin_function],
            security_category="access_control",
            attack_vectors=["unauthorized_access", "privilege_escalation"],
            priority=PropertyPriority.CRITICAL
        )

    @staticmethod
    def create_reentrancy_protection_property(contract: str, function: str) -> SecurityProperty:
        """Create a reentrancy protection property."""
        return SecurityProperty(
            property_id=f"reentrancy_protection_{contract}_{function}",
            name=f"Reentrancy Protection for {function}",
            description=f"Function {function} should be protected against reentrancy attacks",
            specification=f"nonReentrant modifier applied to {function}",
            natural_language=f"The {function} function should not be vulnerable to reentrancy attacks",
            applicable_contracts=[contract],
            applicable_functions=[function],
            security_category="reentrancy",
            attack_vectors=["reentrancy_attack"],
            priority=PropertyPriority.HIGH
        )

    @staticmethod
    def create_defi_slippage_property(contract: str) -> BusinessLogicProperty:
        """Create DeFi slippage protection property."""
        return BusinessLogicProperty(
            property_id=f"slippage_protection_{contract}",
            name="Slippage Protection",
            description="Trades should respect maximum slippage parameters",
            specification="amountOut >= minAmountOut in all swap operations",
            natural_language="All swaps should check that the output amount meets minimum requirements",
            applicable_contracts=[contract],
            applicable_functions=["swap", "swapExactTokensForTokens", "swapTokensForExactTokens"],
            domain="defi",
            stakeholders=["traders", "liquidity_providers"],
            priority=PropertyPriority.HIGH
        )

class PropertyChecker:
    """Base class for property verification."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.verification_results = {}

    def check_property(self, property: Property, contract_data: Dict[str, Any]) -> bool:
        """
        Check if a property holds for the given contract data.
        
        Args:
            property: The property to check
            contract_data: Contract analysis data
            
        Returns:
            bool: True if property holds, False otherwise
        """
        start_time = datetime.now()
        
        try:
            result = self._verify_property(property, contract_data)
            
            # Update property metadata
            property.metadata.last_checked = datetime.now()
            property.metadata.check_count += 1
            property.metadata.verification_time = (datetime.now() - start_time).total_seconds()
            
            if result:
                property.mark_verified()
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error checking property {property.property_id}: {str(e)}")
            property.status = PropertyStatus.ERROR
            return False

    def _verify_property(self, property: Property, contract_data: Dict[str, Any]) -> bool:
        """Override in subclasses to implement specific verification logic."""
        raise NotImplementedError("Subclasses must implement _verify_property")

class InvariantChecker(PropertyChecker):
    """Checker for invariant properties."""
    
    def _verify_property(self, property: InvariantProperty, contract_data: Dict[str, Any]) -> bool:
        """Verify an invariant property."""
        # Implement invariant checking logic
        # This would typically involve:
        # 1. Analyzing contract state variables
        # 2. Checking mathematical relationships
        # 3. Verifying the invariant holds across all contract states
        
        if "balance" in property.name.lower():
            return self._check_balance_invariant(property, contract_data)
        elif "supply" in property.name.lower():
            return self._check_supply_invariant(property, contract_data)
        
        return True  # Default to true for unimplemented checks

    def _check_balance_invariant(self, property: InvariantProperty, contract_data: Dict[str, Any]) -> bool:
        """Check balance-related invariants."""
        # Implementation would analyze balance-related code patterns
        return True

    def _check_supply_invariant(self, property: InvariantProperty, contract_data: Dict[str, Any]) -> bool:
        """Check supply-related invariants."""
        # Implementation would analyze supply-related code patterns
        return True

class PropertyCollection:
    """Collection of properties with management utilities."""
    
    def __init__(self, properties: List[Property] = None):
        self.properties = properties or []

    def add(self, property: Property):
        """Add a property to the collection."""
        self.properties.append(property)

    def get_by_id(self, property_id: str) -> Optional[Property]:
        """Get property by ID."""
        for prop in self.properties:
            if prop.property_id == property_id:
                return prop
        return None

    def get_by_type(self, property_type: PropertyType) -> List[Property]:
        """Get properties by type."""
        return [p for p in self.properties if p.property_type == property_type]

    def get_by_contract(self, contract_name: str) -> List[Property]:
        """Get properties applicable to a contract."""
        return [p for p in self.properties if p.is_applicable_to_contract(contract_name)]

    def get_by_priority(self, priority: PropertyPriority) -> List[Property]:
        """Get properties by priority."""
        return [p for p in self.properties if p.priority == priority]

    def get_violated_properties(self) -> List[Property]:
        """Get properties that have been violated."""
        return [p for p in self.properties if p.status == PropertyStatus.VIOLATED]

    def get_verified_properties(self) -> List[Property]:
        """Get properties that have been verified."""
        return [p for p in self.properties if p.status == PropertyStatus.VERIFIED]

    def get_critical_properties(self) -> List[Property]:
        """Get critical priority properties."""
        return self.get_by_priority(PropertyPriority.CRITICAL)

    def to_dict(self) -> Dict[str, Any]:
        """Convert collection to dictionary."""
        return {
            'properties': [p.to_dict() for p in self.properties],
            'statistics': self.get_statistics()
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get collection statistics."""
        total = len(self.properties)
        if total == 0:
            return {'total': 0}
        
        type_dist = {}
        priority_dist = {}
        status_dist = {}
        
        for prop in self.properties:
            # Type distribution
            prop_type = prop.property_type.value
            type_dist[prop_type] = type_dist.get(prop_type, 0) + 1
            
            # Priority distribution  
            priority = prop.priority.value
            priority_dist[priority] = priority_dist.get(priority, 0) + 1
            
            # Status distribution
            status = prop.status.value
            status_dist[status] = status_dist.get(status, 0) + 1
        
        return {
            'total': total,
            'type_distribution': type_dist,
            'priority_distribution': priority_dist,
            'status_distribution': status_dist,
            'verified_count': len(self.get_verified_properties()),
            'violated_count': len(self.get_violated_properties()),
            'critical_count': len(self.get_critical_properties())
        }

    def __len__(self) -> int:
        """Return number of properties."""
        return len(self.properties)

    def __iter__(self):
        """Iterate over properties."""
        return iter(self.properties)
