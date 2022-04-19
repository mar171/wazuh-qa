import { loginXpack } from '../step-definitions/login/login-xpack';
import { loginOdfe } from '../step-definitions/login/login-odfe';
import { loginBasic } from '../step-definitions/login/login-basic';
import { loginDemo } from '../step-definitions/login/login-demo';

export const LOGIN_TYPE = {
  xpack: () => loginXpack(),
  odfe: () => loginOdfe(),
  basic: () => loginBasic(),
  demo: () => loginDemo()
};

export const ODFE_PASSWORD = 'admin';
export const ODFE_USERNAME = 'admin';
export const OVERVIEW_URL = '/overview/';
export const XPACK_PASSWORD = 'elastic';
export const XPACK_USERNAME = 'elastic';
export const DEMO_USERNAME = 'wazuh';
export const DEMO_PASSWORD = 'ToKDVUeRwxAey3xM';

