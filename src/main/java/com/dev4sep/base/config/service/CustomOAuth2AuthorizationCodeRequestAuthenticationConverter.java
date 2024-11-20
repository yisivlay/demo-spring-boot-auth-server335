package com.dev4sep.base.config.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.time.Instant;
import java.util.Set;

/**
 * @author YISivlay
 */
public class CustomOAuth2AuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {

    private Authentication getAuthenticationFromRequest() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AuthenticationCredentialsNotFoundException("User is not authenticated");
        }

        return authentication;
    }

    /**
     * Converts the incoming HTTP request to an OAuth2AuthorizationCodeRequestAuthenticationToken.
     */
    @Override
    public Authentication convert(HttpServletRequest request) {
        String authorizationCodeValue = request.getParameter("code");
        String redirectUri = request.getParameter("redirect_uri");
        String clientId = request.getParameter("client_id");
        String state = request.getParameter("state");

        if (authorizationCodeValue == null || authorizationCodeValue.isEmpty()) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Authorization code is missing", ""), null
            );
        }
        if (clientId == null || clientId.isEmpty()) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "Client ID is missing", ""), null
            );
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(600);
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(authorizationCodeValue, issuedAt, expiresAt);
        Authentication principal = getAuthenticationFromRequest();
        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                redirectUri,
                clientId,
                principal,
                authorizationCode,
                redirectUri,
                state,
                Set.of("openid", "profile")
        );
    }
}