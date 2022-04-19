Feature: Wazuh version information

  As a kibana user
  I want to check the community redirection
  in order to see Wazuh community

  @about
  Scenario: Check Wazuh version information
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user navigates to About settings
    And The user selects Slack community
    Then The user is redirected to Wazuh Slack community
