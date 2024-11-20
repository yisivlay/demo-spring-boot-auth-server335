package com.dev4sep.base.config.service;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.time.Instant;
import java.util.*;

/**
 * @author YISivlay
 */
public class CustomAccessTokenRequestConverter implements AuthenticationConverter {

    private final RegisteredClientRepository registeredClientRepository;

    public CustomAccessTokenRequestConverter(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        // Extract the authorization code and other parameters from the request
        String authorizationCode = request.getParameter("code");
        String clientId = request.getParameter("client_id");
        String redirectUri = request.getParameter("redirect_uri");
        String state = request.getParameter("state");
        Set<String> scopes = new HashSet<>(Arrays.asList(request.getParameterValues("scope")));

        // Ensure clientId and redirectUri are present
        if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(redirectUri)) {
            throw new IllegalArgumentException("Client ID and Redirect URI must be provided.");
        }

        // Find the registered client using the clientId
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Invalid client ID.");
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(600);
        OAuth2AuthorizationCode authorizationCodeObject = new OAuth2AuthorizationCode(authorizationCode, issuedAt, expiresAt);
        Authentication principal = getAuthenticationFromRequest();
        return new OAuth2AuthorizationCodeRequestAuthenticationToken(redirectUri, clientId, principal, authorizationCodeObject, redirectUri, state, scopes);
    }

    // This method gets the current authentication from the request, typically from the session or security context
    private Authentication getAuthenticationFromRequest() {
        // In a typical scenario, you will retrieve the principal from the security context,
        // assuming Spring Security is in use and the user has already authenticated
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AuthenticationCredentialsNotFoundException("User is not authenticated");
        }

        return authentication;
    }
}

