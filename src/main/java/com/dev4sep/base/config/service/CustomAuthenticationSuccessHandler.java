package com.dev4sep.base.config.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * @author YISivlay
 */
@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        String username = authentication.getName();
        String remoteAddress = details.getRemoteAddress();

        System.out.println("Authentication Success: " + username);
        System.out.println("Remote Address: " + remoteAddress);
        authentication.getAuthorities().forEach(authority -> {
            System.out.println("Granted Authority: " + authority.getAuthority());
        });
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write("Authentication was successful for user: " + username);
        String redirectUrl = "/home";
        response.sendRedirect(redirectUrl);
    }
}
