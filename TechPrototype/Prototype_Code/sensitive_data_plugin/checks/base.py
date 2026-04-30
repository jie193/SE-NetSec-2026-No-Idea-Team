# Base detector class for all sensitive data detection
import bandit
from bandit.core import issue
from sensitive_data_plugin.utils.filters import should_ignore
from sensitive_data_plugin.utils.constants import RULES

class BaseDetector:
    """Base class for all sensitive data detectors
    
    This class provides common functionality for all detectors, including:
    - Issue creation
    - False positive filtering
    - Rule information access
    """
    
    def __init__(self):
        pass
    
    def create_issue(self, rule_id, severity, confidence, text, lineno=None):
        """Create a standardized Issue object
        
        Args:
            rule_id: The rule ID (e.g., 'SC100')
            severity: The severity level (bandit.LOW, bandit.MEDIUM, bandit.HIGH)
            confidence: The confidence level (bandit.LOW, bandit.MEDIUM, bandit.HIGH)
            text: The issue description
            lineno: The line number of the issue
            
        Returns:
            bandit.Issue: The created Issue object
        """
        cwe_mapping = {
            'SC100': issue.Cwe.HARD_CODED_PASSWORD,
            'SC101': issue.Cwe.HARD_CODED_PASSWORD,
            'SC102': issue.Cwe.HARD_CODED_PASSWORD,
            'SC200': issue.Cwe.BROKEN_CRYPTO,
            'SC201': issue.Cwe.BROKEN_CRYPTO,
            'SC202': issue.Cwe.BROKEN_CRYPTO,
            'SC203': issue.Cwe.INADEQUATE_ENCRYPTION_STRENGTH,
        }
        
        cwe = cwe_mapping.get(rule_id, issue.Cwe.HARD_CODED_PASSWORD)
        
        return bandit.Issue(
            severity=severity,
            confidence=confidence,
            cwe=cwe,
            text=text,
            lineno=lineno
        )
    
    def get_rule_info(self, rule_id):
        """Get information about a specific rule
        
        Args:
            rule_id: The rule ID (e.g., 'SC100')
            
        Returns:
            dict: Rule information including name, description, severity, and confidence
        """
        return RULES.get(rule_id, {})
    
    def get_severity(self, rule_id):
        """Get the severity level for a rule
        
        Args:
            rule_id: The rule ID
            
        Returns:
            int: The severity level (bandit.LOW, bandit.MEDIUM, bandit.HIGH)
        """
        severity_map = {
            'LOW': bandit.LOW,
            'MEDIUM': bandit.MEDIUM,
            'HIGH': bandit.HIGH,
        }
        rule_info = self.get_rule_info(rule_id)
        return severity_map.get(rule_info.get('severity', 'MEDIUM'), bandit.MEDIUM)
    
    def get_confidence(self, rule_id):
        """Get the confidence level for a rule
        
        Args:
            rule_id: The rule ID
            
        Returns:
            int: The confidence level (bandit.LOW, bandit.MEDIUM, bandit.HIGH)
        """
        confidence_map = {
            'LOW': bandit.LOW,
            'MEDIUM': bandit.MEDIUM,
            'HIGH': bandit.HIGH,
        }
        rule_info = self.get_rule_info(rule_id)
        return confidence_map.get(rule_info.get('confidence', 'MEDIUM'), bandit.MEDIUM)
    
    def is_ignored(self, context, value, name=None):
        """Check if a detection should be ignored
        
        Args:
            context: Bandit context object
            value: The value to check
            name: The variable/argument name to check (optional)
            
        Returns:
            bool: True if the detection should be ignored
        """
        return should_ignore(context, value, name)
    
    def detect(self, context):
        """Main detection method to be implemented by subclasses
        
        Args:
            context: Bandit context object
            
        Returns:
            bandit.Issue or None: The detected issue, or None if no issue found
        """
        raise NotImplementedError("Subclasses must implement detect method")
