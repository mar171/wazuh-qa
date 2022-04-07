import { When } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible } from '../../../utils/driver';
import {avaiableAgent} from '../../../pageobjects/management/groups/manage.agent.page';

When('The user clicks on a existent agent', () => {
  elementIsVisible(avaiableAgent);
  clickElement(avaiableAgent);
});
