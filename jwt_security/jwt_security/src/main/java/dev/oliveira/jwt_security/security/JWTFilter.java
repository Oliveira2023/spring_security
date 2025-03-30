package dev.oliveira.jwt_security.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JWTFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JWTFilter.class);
    private static final String HEADER = "Authorization";
    private static final String PREFIX = "Bearer ";

    private final JWTValidator jwtValidator;

    public JWTFilter(JWTValidator jwtValidator) {
        this.jwtValidator = jwtValidator;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // SOLUÇÃO CRÍTICA: Não aplicar este filtro a nenhuma rota de autenticação
        // e sempre aplicar apenas se existir um token no cabeçalho
        String path = request.getServletPath();
        String authHeader = request.getHeader(HEADER);

        // Sempre pular o filtro para rotas de auth, login, cadastro, etc
        if (path.startsWith("/auth") ||
                path.startsWith("/login") ||
                path.startsWith("/h2-console") ||
                path.equals("/")) {
            logger.info("Pulando filtro para rota pública: {}", path);
            return true;
        }

        // Se não tem token no cabeçalho, também pulamos o filtro
        // Isso é crítico para evitar recursão
        if (authHeader == null || !authHeader.startsWith(PREFIX)) {
            logger.info("Pulando filtro por ausência de token: {}", path);
            return true;
        }

        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        logger.info("===> Executando filtro JWT para: {}", request.getServletPath());

        // SEGURANÇA EXTRA: Verificar novamente que temos um token
        String authHeader = request.getHeader(HEADER);

        logger.info(PREFIX + "Authorization header: {}", authHeader);

        if (authHeader == null || !authHeader.startsWith(PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = authHeader.replace(PREFIX, "").trim();

            // Não processamos token vazio
            if (token.isEmpty()) {
                filterChain.doFilter(request, response);
                return;
            }

            // EVITAR LOOP: Não verificar o token se já estamos autenticados
            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                filterChain.doFilter(request, response);
                return;
            }

            if (jwtValidator.isTokenValid(token)) {
                UserDetails userDetails = jwtValidator.getUserDetailsFromToken(token);

                if (userDetails != null) {
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails, null, userDetails.getAuthorities());

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }

            filterChain.doFilter(request, response);

        } catch (Exception e) {
            logger.error("Erro ao processar o token: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            filterChain.doFilter(request, response);
        }
    }
}