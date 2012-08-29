/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.springframework.security.oauth.examples.sparklr.oauth;

import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * @author Dave Syer
 * @author Jakub Jirutka
 */
public class RemoteTokenServices implements ResourceServerTokenServices {

    protected final Log logger = LogFactory.getLog(getClass());

    private RestOperations restTemplate = new RestTemplate();
    private String checkTokenEndpointUrl;
    private String clientId;
    private String clientSecret;
    private HttpMethod method = HttpMethod.POST;


    @SuppressWarnings("unchecked")
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", getAuthorizationHeader(clientId, clientSecret));

        Map<String, Object> map = requestTokenInfo(checkTokenEndpointUrl, method, accessToken, headers);

        if (map.containsKey("error")) {
            logger.debug("check_token returned error: " + map.get("error"));
            throw new InvalidTokenException(accessToken);
        }

        Assert.state(map.containsKey("client_id"), "Client id must be present in response from auth server");
        String remoteClientId = (String) map.get("client_id");

        Set<String> scope = new HashSet<String>();
        if (map.containsKey("scope")) {
            Collection<String> values = (Collection<String>) map.get("scope");
            scope.addAll(values);
        }
        DefaultAuthorizationRequest clientAuthentication = new DefaultAuthorizationRequest(remoteClientId, scope);

        if (map.containsKey("resource_ids") || map.containsKey("client_authorities")) {

            Set<String> resourceIds = new HashSet<String>();
            if (map.containsKey("resource_ids")) {
                Collection<String> values = (Collection<String>) map.get("resource_ids");
                resourceIds.addAll(values);
            }

            Set<GrantedAuthority> clientAuthorities = new HashSet<GrantedAuthority>();
            if (map.containsKey("client_authorities")) {
                Collection<String> values = (Collection<String>) map.get("client_authorities");
                clientAuthorities.addAll(getAuthorities(values));
            }

            BaseClientDetails clientDetails = new BaseClientDetails();
            clientDetails.setClientId(remoteClientId);
            clientDetails.setResourceIds(resourceIds);
            clientDetails.setAuthorities(clientAuthorities);
            clientAuthentication.addClientDetails(clientDetails);
        }

        Set<GrantedAuthority> userAuthorities = new HashSet<GrantedAuthority>();
        if (map.containsKey("user_authorities")) {
            Collection<String> values = (Collection<String>) map.get("user_authorities");
            userAuthorities.addAll(getAuthorities(values));
        } else {
            // User authorities had better not be empty or we might mistake user for unauthenticated
            userAuthorities.addAll(getAuthorities(scope));
        }

        String username = (String) map.get("username");
        UserDetails user = new User(username, "", userAuthorities);
        Authentication userAuthentication = new UsernamePasswordAuthenticationToken(user, null, userAuthorities);

        clientAuthentication.setApproved(true);
        return new OAuth2Authentication(clientAuthentication, userAuthentication);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
        throw new UnsupportedOperationException("Not supported: read access token");
    }

    private Set<GrantedAuthority> getAuthorities(Collection<String> authorities) {
        Set<GrantedAuthority> result = new HashSet<GrantedAuthority>();
        for (String authority : authorities) {
            result.add(new SimpleGrantedAuthority(authority));
        }
        return result;
    }

    private String getAuthorizationHeader(String clientId, String clientSecret) {
        String creds = String.format("%s:%s", clientId, clientSecret);
        try {
            return "Basic " + new String(Base64.encode(creds.getBytes("UTF-8")));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Could not convert String");
        }
    }


    @SuppressWarnings("rawtypes")
    private Map<String, Object> requestTokenInfo(String path, HttpMethod method, String accessToken, HttpHeaders headers) {
        Map<String, Object> result;

        if (headers.getContentType() == null) {
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        }

        if (method == HttpMethod.GET) {
            Map map = restTemplate.exchange(path, HttpMethod.GET,
                    new HttpEntity<MultiValueMap<String, String>>(null, headers), Map.class, accessToken).getBody();
            result = (Map<String, Object>) map;

        } else if (method == HttpMethod.POST) {
            MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
            formData.add("token", accessToken);

            Map map = restTemplate.exchange(path, HttpMethod.POST,
                    new HttpEntity<MultiValueMap<String, String>>(formData, headers), Map.class).getBody();
            result = (Map<String, Object>) map;

        } else {
            throw new IllegalArgumentException("Unsupported method " + method);
        }

        return result;
    }


    public void setRestTemplate(RestOperations restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
        this.checkTokenEndpointUrl = checkTokenEndpointUrl;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public HttpMethod getMethod() {
        return method;
    }

    public void setMethod(HttpMethod method) {
        this.method = method;
    }

}
