import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible } from '../../../utils/driver';
import {addSelectedItemButton} from '../../../pageobjects/management/groups/manage.agent.page';

When('The user clicks the add a selected item option', () => {
  elementIsVisible(addSelectedItemButton);
  clickElement(addSelectedItemButton);
});
