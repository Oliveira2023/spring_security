package dev.oliveira.jwt_security.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class JWTValidator {

    private static final Logger logger = LoggerFactory.getLogger(JWTValidator.class);
    private final SecretKey key;

    public JWTValidator(@Value("${jwt.secret:defaultSecretKey12345678901234567890}") String secretKey) {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    // SOLUÇÃO DE EMERGÊNCIA: Métodos simplificados para evitar recursão
    public boolean isTokenValid(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // Verificar expiração básica
            Date expiration = claims.getExpiration();
            if (expiration != null && expiration.before(new Date())) {
                return false;
            }

            return true;
        } catch (Exception e) {
            logger.error("Erro validando token: {}", e.getMessage());
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public UserDetails getUserDetailsFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String username = claims.getSubject();
            List<String> roles = claims.get("roles", List.class);

            if (username == null || roles == null) {
                logger.error("Token inválido: usuário ou roles ausentes");
                return null;
            }

            // Criar authorities com prefixo ROLE_
            List<SimpleGrantedAuthority> authorities = roles.stream()
                    .map(role -> !role.startsWith("ROLE_") ?
                            new SimpleGrantedAuthority("ROLE_" + role) :
                            new SimpleGrantedAuthority(role))
                    .collect(Collectors.toList());

            logger.info("Autoridades construídas: {}", authorities);

            return new User(username, "", authorities);

        } catch (Exception e) {
            logger.error("Erro extraindo UserDetails: {}", e.getMessage());
            return null;
        }
    }

    // Estes métodos são deixados mais para compatibilidade,
    // mas não são usados diretamente no fluxo principal
    public String extractUsername(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .get("roles", List.class);
        } catch (Exception e) {
            return List.of();
        }
    }
}