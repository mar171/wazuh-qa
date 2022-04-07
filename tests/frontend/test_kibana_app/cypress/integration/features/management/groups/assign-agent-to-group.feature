Feature: Assign an existent agent to an existent group

  As a kibana user
  i want to add an existent to a new group
  in order to check if the agent could be added to a new group.

  Scenario: Should assign an agent to a new group
    Given The kibana admin user is logged in using xpack and the wazuh logo is displayed
    When The user navigates to the group page
    And The user navigates to te managment page
    And The user clicks on the manage agent option
    And The user clicks on a existent agent
    And The user clicks the add a selected item option
    And The added label is displayed
    And The user applies the changes
    #Then The user checks if the group label is added to the agent