import { When } from 'cypress-cucumber-preprocessor/steps';
import { elementIsVisible, clickElement} from '../../../utils/driver';
import { applyChangesButton } from '../../../pageobjects/management/groups/manage.agent.page';

When('The user applies the changes', () => {
  elementIsVisible(applyChangesButton);
  clickElement(applyChangesButton);
});
