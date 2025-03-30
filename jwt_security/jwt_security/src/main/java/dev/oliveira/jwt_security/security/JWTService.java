package dev.oliveira.jwt_security.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

@Component
public class JWTService {

    private final SecretKey key;
    private static final long EXPIRATION_MINUTES = 60;

    public JWTService(@Value("${jwt.secret:defaultSecretKey12345678901234567890}") String secretKey) {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes());
    }
    public String generateToken(String userName, List<String> roles) {

        List<String> formattedRoles = roles.stream()
                .map(role -> {
                    if (!role.startsWith("ROLE_")) {
                        return "ROLE_" + role;
                    }
                    return role;
                }).toList();

        return Jwts.builder()
                .subject(userName)
                .claim("roles", formattedRoles)
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from((Instant.now().plus(EXPIRATION_MINUTES, ChronoUnit.MINUTES))))
                .signWith(key)
                .compact();
    }
}
