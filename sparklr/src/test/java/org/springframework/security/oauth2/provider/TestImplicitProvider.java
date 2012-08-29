package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestImplicitProvider {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);

	private String cookie;

	@BeforeOAuth2Context
	public void loginAndExtractCookie() {

		MultiValueMap<String, String> formData;
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("j_username", "marissa");
		formData.add("j_password", "koala");

		String location = "/sparklr2/login.do";
		ResponseEntity<Void> result = serverRunning.postForStatus(location, formData);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		String cookie = result.getHeaders().getFirst("Set-Cookie");

		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		this.cookie = cookie;

	}

	@Test(expected = UserRedirectRequiredException.class)
	@OAuth2ContextConfiguration(resource = AutoApproveImplicit.class, initialize = false)
	public void testRedirectRequiredForAuthentication() throws Exception {
		context.getAccessToken();
	}

	@Test
	@OAuth2ContextConfiguration(resource = AutoApproveImplicit.class, initialize = false)
	public void testPostForAutomaticApprovalToken() throws Exception {
		context.getAccessTokenRequest().setCookie(cookie);
		assertNotNull(context.getAccessToken());
	}

	@Test
	@OAuth2ContextConfiguration(resource = NonAutoApproveImplicit.class, initialize = false)
	public void testPostForNonAutomaticApprovalToken() throws Exception {
		context.getAccessTokenRequest().setCookie(cookie);
		try {
			assertNotNull(context.getAccessToken());
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserRedirectRequiredException e) {
			// ignore
		}
		// add user approval parameter for the second request
		context.getAccessTokenRequest().add(AuthorizationRequest.USER_OAUTH_APPROVAL, "true");
		assertNotNull(context.getAccessToken());
	}

	static class AutoApproveImplicit extends ImplicitResourceDetails {
		public AutoApproveImplicit(Object target) {
			super();
			setClientId("my-less-trusted-autoapprove-client");
			setScope(Arrays.asList("read"));
			setId(getClientId());
			setPreEstablishedRedirectUri("http://anywhere");
			TestImplicitProvider test = (TestImplicitProvider) target;
			setAccessTokenUri(test.serverRunning.getUrl("/sparklr2/oauth/authorize"));
			setUserAuthorizationUri(test.serverRunning.getUrl("/sparklr2/oauth/authorize"));
		}
	}

	static class NonAutoApproveImplicit extends AutoApproveImplicit {
		public NonAutoApproveImplicit(Object target) {
			super(target);
			setClientId("my-less-trusted-client");
		}
	}

}
