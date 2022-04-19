import { hrefSlackCommunityLink } from "../../../utils/common-constanst";
import { validateLink } from "../../../utils/driver";


Then('The user is redirected to Wazuh Slack community', () => {
    validateLink("a[aria-label='Wazuh Slack']", hrefSlackCommunityLink)
});
