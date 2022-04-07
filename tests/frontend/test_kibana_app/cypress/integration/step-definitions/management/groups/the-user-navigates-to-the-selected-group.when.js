import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible} from '../../../utils/driver';
import { selectedGroup } from '../../../pageobjects/management/groups/groups.page';

When('The user navigates to te managment page', () => {
  elementIsVisible(selectedGroup);
  clickElement(selectedGroup);
});
