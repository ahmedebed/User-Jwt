package com.example.UserJwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component // Marks this class as a Spring-managed component.
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // This filter will be executed once per request as part of Spring Security.

    private final JwtService jwtService; // Service to handle JWT-related operations.
    private final UserDetailsService userDetailsService; // Service to retrieve user details.

    // Constructor for dependency injection of JwtService and UserDetailsService.
    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    // This method handles the actual filtering logic for each request.
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request, // The current HTTP request.
            @NonNull HttpServletResponse response, // The current HTTP response.
            @NonNull FilterChain filterChain // The filter chain to pass the request further.
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        // Retrieves the Authorization header from the request.

        final String jwt; // Variable to store the JWT token.
        final String userEmail; // Variable to store the extracted user email/username.

        // Checks if the Authorization header is null or doesn't start with "Bearer ".
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            // If no token is found, skip authentication and continue the filter chain.
            return;
        }

        jwt = authHeader.substring(7);
        // Extracts the token by removing the "Bearer " prefix.

        userEmail = jwtService.extractUsername(jwt);
        // Extracts the username (subject) from the token.

        // If a username is extracted and no authentication is already set.
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // Loads the user details from the database.

            if (jwtService.isTokenValid(jwt, userDetails)) {
                // Validates the token (checks if it belongs to the user and isn't expired).

                // Creates an authentication token for the user.
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, // Authenticated user details.
                        null, // No credentials (password isn't needed here).
                        userDetails.getAuthorities() // User roles/authorities.
                );

                // Adds additional details about the request.
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Stores the authentication token in the SecurityContext.
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
        // Continues processing the next filter in the chain.
    }
}
