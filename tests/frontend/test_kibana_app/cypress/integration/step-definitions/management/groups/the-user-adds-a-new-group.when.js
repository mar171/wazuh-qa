import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible, fillField} from '../../../utils/driver';
import { addNewGroup, saveNameButton, groupName} from '../../../pageobjects/management/groups/groups.page';

When('The user adds a new group', () => {
  elementIsVisible(addNewGroup);
  clickElement(addNewGroup);
  elementIsVisible(groupName);
  fillField(groupName,'test');
  elementIsVisible(saveNameButton);
  clickElement(saveNameButton);
});
