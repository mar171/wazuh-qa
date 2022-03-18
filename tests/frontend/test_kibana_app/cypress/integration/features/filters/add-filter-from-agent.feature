Feature: Validate that the added filter label is displayed 
   
    As Wazuh user 
    i want to set a new filter from the agent page 
    in order to manage them
  
   Scenario Outline: The user add a new filer
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user nav to the agent page 
    And The user navigates to <Module Name>
    And The user add a new filter
    Examples:
      | Module Name           |
      | Security Events       |
      | Integrity Monitoring  |
      | SCA                   |
      | System Auditing       |
      | Vulnerabilities       |
      | Mitre & Attack        |