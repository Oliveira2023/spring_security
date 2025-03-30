package dev.oliveira.jwt_security.service;

import dev.oliveira.jwt_security.model.User;
import dev.oliveira.jwt_security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public User createUser(User user) {
        if (userRepository.findByUsername(user.getName()) != null) {
            throw new RuntimeException("Usuário já existe");
        }
        String pass = user.getPassword();
        user.setPassword(passwordEncoder.encode(pass));
         return  userRepository.save(user);
    }
    public Iterable<User> getAllUsers() {
        System.out.println("Listando todos os usuários");
        return userRepository.findAll();
    }
}
