package dev.oliveira.jwt_security.controller;

import dev.oliveira.jwt_security.model.User;
import dev.oliveira.jwt_security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @PostMapping
    public ResponseEntity<?> createUser(@RequestBody User user) {
        try{
            User createdUser = userService.createUser(user);
            return ResponseEntity.status(HttpStatus.OK).body(createdUser);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Erro ao tentar criar o usuário " + e.getMessage());
        }
    }

    @GetMapping
    public ResponseEntity<?> getAllUsers() {
        try {
            return ResponseEntity.status(HttpStatus.OK).body(userService.getAllUsers());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Erro ao tentar listar os usuários" + e.getMessage());
        }
    }
}
