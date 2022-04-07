import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible } from '../../../utils/driver';
import { wazuhMenuButton, managementButton, groupsLink} from '../../../pageobjects/wazuh-menu/wazuh-menu.page';

When('The user navigates to the group page', () => {
  elementIsVisible(wazuhMenuButton);
  clickElement(wazuhMenuButton);
  elementIsVisible(managementButton);
  clickElement(managementButton);
  elementIsVisible(groupsLink);
  clickElement(groupsLink);
});
