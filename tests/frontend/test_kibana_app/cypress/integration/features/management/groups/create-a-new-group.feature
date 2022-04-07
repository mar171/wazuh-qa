Feature: Create a new group

  As a kibana user
  i want to create a new group
  in order to assign an agent to it.

  Scenario: Should create a new group
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user navigates to the group page
    And The user adds a new group
    Then The user checks if the new group was created