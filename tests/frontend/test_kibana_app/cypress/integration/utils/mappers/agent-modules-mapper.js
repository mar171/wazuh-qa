import {
agSecurityEventsLink,
agIntegrityMonitoringLink,
agSCALink,
agSystemAuditingLink,
agVulnerabilitiesLink,
agMitreAttackLink
  } from '../../pageobjects/agents/agents.page';
  
  export const AGENT_MODULES = {
    'Security Events': agSecurityEventsLink,
    'Integrity Monitoring': agIntegrityMonitoringLink,
    'SCA': agSCALink,
    'System Auditing': agSystemAuditingLink,
    'Vulnerabilities': agVulnerabilitiesLink,
    'Mitre & Attack': agMitreAttackLink
  }