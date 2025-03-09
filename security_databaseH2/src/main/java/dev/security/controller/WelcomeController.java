package dev.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {
    @GetMapping
    public String welcome() {
        return "Welcome to the Security API";
    }
    @GetMapping("/users")
    public String users() {
        return "Welcome Users";
    }
    @GetMapping("/managers")
    public String managers() {
        return "Welcome Managers";
    }
    @GetMapping("/public/info")
    public String getInfo() {
        return "Informações públicas acessíveis sem login";
    }
}
