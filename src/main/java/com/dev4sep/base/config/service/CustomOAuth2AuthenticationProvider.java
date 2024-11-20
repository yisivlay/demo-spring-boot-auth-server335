package com.dev4sep.base.config.service;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

/**
 * @author YISivlay
 */
public class CustomOAuth2AuthenticationProvider implements AuthenticationProvider {

    private final OAuth2AuthorizationService authorizationService;

    public CustomOAuth2AuthenticationProvider(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // Check if the incoming authentication token is of type OAuth2AuthorizationCodeRequestAuthenticationToken
        if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken) {
            OAuth2AuthorizationCodeRequestAuthenticationToken grantAuthenticationToken =
                    (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

            // Extract authorization code or other details from the token
            OAuth2AuthorizationCode authorizationCode = grantAuthenticationToken.getAuthorizationCode();
            String clientId = grantAuthenticationToken.getClientId();
            String redirectUri = grantAuthenticationToken.getRedirectUri();

            // Ensure that the authorization code is not null or empty
            if (authorizationCode == null) {
                throw new AuthenticationCredentialsNotFoundException("Authorization code is missing or invalid");
            }

            // Custom validation logic for authorization code
            if (!isValidAuthorizationCode(authorizationCode)) {
                throw new AuthenticationException("Invalid authorization code") {
                };
            }

            // Example: Retrieve user details or validate against a database or OAuth2 service
            // Validate the clientId, for example by checking it against a known list or database
            if (!isValidClient(clientId)) {
                throw new AuthenticationException("Invalid client") {
                };
            }

            // Validate the redirect URI
            if (!isValidRedirectUri(redirectUri)) {
                throw new AuthenticationException("Invalid redirect URI") {
                };
            }

            // If everything checks out, return an authenticated token with the relevant details
            // Ensure that you pass the correct data to the authentication token (e.g., OAuth2AuthorizationCode)
            return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                    grantAuthenticationToken.getAuthorizationUri(),
                    clientId,
                    (Authentication) grantAuthenticationToken.getPrincipal(),
                    authorizationCode,
                    null,
                    grantAuthenticationToken.getState(),
                    grantAuthenticationToken.getScopes()
            );
        }

        // If the authentication token is not of the expected type, return null (let Spring Security handle it)
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }

    // Custom validation methods for authorization code, client, and redirect URI

    private boolean isValidAuthorizationCode(OAuth2AuthorizationCode authorizationCode) {
        // In a real application, you would query your database or OAuth2 token store to validate the authorization code
        String tokenValue = authorizationCode.getTokenValue();

        // Example: Check if the token exists in a token store or database
        OAuth2Authorization storedCode = authorizationService.findByToken(tokenValue, null);

        return storedCode != null && !storedCode.getAccessToken().isExpired();
    }

    private boolean isValidClient(String clientId) {
        return clientId.equals("oidc-client");
    }

    private boolean isValidRedirectUri(String redirectUri) {
        return redirectUri != null && redirectUri.startsWith("http://127.0.0.1:8080/authorized");
    }
}
