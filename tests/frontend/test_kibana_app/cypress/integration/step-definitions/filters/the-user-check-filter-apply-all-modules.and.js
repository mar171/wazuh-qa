import { And } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, getElement} from '../../utils/driver';
import {
    pinnedFilter
  } from '../../pageobjects/filters/filters.page';
  import {
    wazuhMenuButton,
    modulesButton,
    pciDssLink
  } from '../../pageobjects/wazuh-menu/wazuh-menu.page';
And('The user check if the filter is apply across the modules', () => {
    clickElement(wazuhMenuButton);
    clickElement(modulesButton);
    clickElement(pciDssLink);
    getElement(pinnedFilter)
     .should('exist')
     .should('be.visible');
  });