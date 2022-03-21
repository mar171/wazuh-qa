import { And } from 'cypress-cucumber-preprocessor/steps';
import { clickElement, elementIsVisible} from '../../utils/driver';
import {
    firstAgentList
  } from '../../pageobjects/agents/agents.page';
import { AGENT_MODULES } from '../../utils/mappers/agent-modules-mapper';
   
And('The user navigates to {}', (moduleName) => {
  //elementIsVisible(firstAgentList);
  //clickElement(firstAgentList);
  elementIsVisible(AGENT_MODULES[moduleName]);
  clickElement(AGENT_MODULES[moduleName]);
});