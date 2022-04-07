import { Then } from 'cypress-cucumber-preprocessor/steps';
import { elementIsVisible, elementTextIncludes} from '../../../utils/driver';
import { testGroup} from '../../../pageobjects/management/groups/groups.page';

Then('The user checks if the new group was created', () => {
  elementIsVisible(testGroup);
  elementTextIncludes(testGroup,"test");
});
