package com.dev4sep.base.config.service;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;

/**
 * @author YISivlay
 */
public class CustomAuthenticationProvidersConsumer implements AuthenticationProvider {

    private boolean isAuthenticated = false;

    @Override
    public Authentication authenticate(Authentication authentication) {
        if (authentication instanceof OAuth2AuthorizationCodeAuthenticationToken) {
            OAuth2AuthorizationCodeAuthenticationToken authorizationToken =
                    (OAuth2AuthorizationCodeAuthenticationToken) authentication;
            String code = authorizationToken.getCode();
            String redirectUri = authorizationToken.getRedirectUri();
            Authentication principal = getAuthenticationFromRequest();
            if (code == null || code.isEmpty()) {
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error("Authorization code is missing or invalid"), null);
            }
            if (!isValidRedirectUri(redirectUri)) {
                throw new AuthenticationException("Invalid redirect URI") {
                };
            }
            return new OAuth2AuthorizationCodeAuthenticationToken(
                    code,
                    principal,
                    redirectUri,
                    null
            );
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private Authentication getAuthenticationFromRequest() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AuthenticationCredentialsNotFoundException("User is not authenticated");
        }

        return authentication;
    }

    private boolean isValidRedirectUri(String redirectUri) {
        return redirectUri != null && redirectUri.startsWith("http://127.0.0.1:8080/authorized");
    }

    // Custom setting or logic to modify the provider behavior
    public void setAuthenticated(boolean isAuthenticated) {
        this.isAuthenticated = isAuthenticated;
    }
}
