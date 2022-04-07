import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible } from '../../../utils/driver';
import { manageAgentButton} from '../../../pageobjects/management/groups/groups.page';

When('The user clicks on the manage agent option', () => {
  elementIsVisible(manageAgentButton);
  clickElement(manageAgentButton);
});
