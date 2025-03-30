package dev.oliveira.jwt_security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {
    @GetMapping
    public String welcome() {
        return "Welcome to the JWT Security Application!";
    }

    @GetMapping("managers")
    public String managers() {
        return "Manager Welcome to the JWT Security Application!";
    }
}
