package com.example.UserJwt.config;

import io.jsonwebtoken.Claims; // Represents the claims (payload) in a JWT.
import io.jsonwebtoken.Jwts; // Used for parsing and creating JWTs.
import io.jsonwebtoken.SignatureAlgorithm; // Specifies the signing algorithm.
import io.jsonwebtoken.io.Decoders; // Decodes Base64 keys.
import io.jsonwebtoken.security.Keys; // Generates cryptographic keys.
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key; // Represents the signing key.
import java.util.Date; // Represents date/time.
import java.util.HashMap; // Represents additional claims in JWT.
import java.util.Map; // Generic map for storing claims.
import java.util.function.Function; // Functional interface for claims extraction.

@Service // Marks this as a Spring-managed service.
public class JwtService {

    // Secret key used for signing and verifying tokens.
    private static final String SECRET_KEY = "your_long_base64_encoded_secret_key";

    // Extracts the username (subject) from the token.
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
        // Retrieves the "sub" (subject) field from the token claims.
    }

    // Extracts a specific claim from the token.
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        // Parses and retrieves all claims from the token.
        return claimsResolver.apply(claims);
        // Applies the claims resolver to extract the desired claim.
    }

    // Generates a JWT token with only the username.
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
        // Calls the overloaded method with an empty map for additional claims.
    }

    // Generates a JWT token with extra claims.
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims) // Adds custom claims to the token.
                .setSubject(userDetails.getUsername()) // Sets the subject (username).
                .setIssuedAt(new Date(System.currentTimeMillis())) // Sets the token's issue time.
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                // Sets the token's expiration time (24 minutes).
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                // Signs the token using the secret key and HMAC SHA-256.
                .compact(); // Builds and returns the token.
    }

    // Validates the token by comparing the username and checking expiration.
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        // Extracts the username from the token.
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        // Returns true if the username matches and the token isn't expired.
    }

    // Checks if the token is expired.
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
        // Returns true if the expiration date is before the current date.
    }

    // Extracts the expiration date from the token.
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
        // Retrieves the "exp" (expiration) field from the token claims.
    }

    // Parses the token and retrieves all its claims.
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) // Sets the signing key for validation.
                .build()
                .parseClaimsJws(token) // Parses the token and verifies its signature.
                .getBody(); // Returns the payload (claims).
    }

    // Decodes the secret key and creates a cryptographic key.
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        // Decodes the Base64-encoded secret key.
        return Keys.hmacShaKeyFor(keyBytes);
        // Creates a HMAC-SHA-256 key from the decoded bytes.
    }
}
