package com.dev4sep.base.config.service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @author YISivlay
 */
@Component
public class CustomErrorResponseHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        OAuth2Error error;
        if (exception instanceof OAuth2AuthorizationCodeRequestAuthenticationException) {
            error = new OAuth2Error("invalid_request", "Invalid request", null);
        } else if (exception instanceof OAuth2AuthorizationCodeRequestAuthenticationException) {
            error = new OAuth2Error("invalid_client", "Client authentication failed", null);
        } else {
            error = new OAuth2Error("server_error", "Internal server error", null);
        }

        // Create a JSON response body with error details
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("application/json");

        String errorResponse = String.format(
                "{\"error\": \"%s\", \"error_description\": \"%s\"}",
                error.getErrorCode(),
                error.getDescription()
        );

        response.getWriter().write(errorResponse);
    }
}
