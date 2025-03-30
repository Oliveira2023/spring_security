package dev.oliveira.jwt_security.controller;

import dev.oliveira.jwt_security.dtos.JwtResponse;
import dev.oliveira.jwt_security.dtos.LoginRequest;
import dev.oliveira.jwt_security.security.JWTService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;

    public AuthController(AuthenticationManager authenticationManager, JWTService jwtService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    @PostMapping
    public ResponseEntity<?> authenticate(@RequestBody LoginRequest loginRequest) {
        logger.info("===> Tentativa de autenticação para usuário: {}", loginRequest.getUsername());

        try {
            // Autenticar o usuíario
            System.out.println("===> Tentativa de autenticação para usuário: " + loginRequest.getUsername());
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword())
            );

            logger.info("===> Autenticação bem-sucedida para: {}", loginRequest.getUsername());

            // Configurar o contexto de segurança
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Obter os detalhes do usuário autenticado
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Extrair os roles do usuário
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            logger.info("===> Roles do usuário: {}", roles);

            // Gerar o token JWT
            String jwt = jwtService.generateToken(userDetails.getUsername(), roles);
            logger.info("===> Token JWT gerado com sucesso");

            // Retornar o token com outros dados do usuário se necessário
            return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUsername(), roles));

        } catch (BadCredentialsException e) {
            logger.error("===> Credenciais inválidas para: {}", loginRequest.getUsername());
            return ResponseEntity.status(401).body("Credenciais inválidas");
        } catch (Exception e) {
            logger.error("===> Erro na autenticação: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body("Erro ao autenticar: " + e.getMessage());
        }
    }
}