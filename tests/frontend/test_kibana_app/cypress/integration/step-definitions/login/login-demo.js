import { DEMO_PASSWORD, DEMO_USERNAME } from '../../utils/login-constants';
import {
  buttonSubmitSelector,
  inputPasswordSelector,
  inputUsernameSelector,
} from '../../pageobjects/login/odef-login.page';
import { clickElement, fillField } from '../../utils/driver';

const fillUsernameFieldDemo = (userName) => {
  fillField(inputUsernameSelector, userName);
  return this;
};

const fillPasswordFieldDemo = (password) => {
  fillField(inputPasswordSelector, password);
  return this;
};

const clickSubmitButtonDemo = () => {
  clickElement(buttonSubmitSelector);
};

const loginDemo = () => {
  fillUsernameFieldDemo(DEMO_USERNAME);
  fillPasswordFieldDemo(DEMO_PASSWORD);
  clickSubmitButtonDemo();
};

export { loginDemo };
