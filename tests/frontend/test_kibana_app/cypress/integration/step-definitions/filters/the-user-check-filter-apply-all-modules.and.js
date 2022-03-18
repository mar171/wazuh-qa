import { Then } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, getElement} from '../../utils/driver';
import {
    pinnedFilter
  } from '../../pageobjects/filters/filters.page';
Then('The user check if the filter is apply across the modules', () => {
    getElement(pinnedFilter)
     .should('exist')
     .should('be.visible');
  });