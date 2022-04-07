import { When } from 'cypress-cucumber-preprocessor/steps';
import { elementIsVisible, elementTextIncludes} from '../../../utils/driver';
import { addedLabel } from '../../../pageobjects/management/groups/manage.agent.page';

When('The added label is displayed', () => {
  elementIsVisible(addedLabel);
  elementTextIncludes(addedLabel, "Added: 1");
});
