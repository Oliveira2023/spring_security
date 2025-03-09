package dev.security.init;

import dev.security.model.Usuario;
import dev.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class StartAplication implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional
    @Override
    public void run(String... args) throws Exception {
        Usuario usuario = userRepository.findByUsername("admin");
        if(usuario == null){
            Usuario admin = new Usuario();
            admin.setName("admin");
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin"));
            admin.getRoles().add("ADMIN");
            userRepository.save(admin);
        }
        usuario = userRepository.findByUsername("user");
        if(usuario == null){
            Usuario user = new Usuario();
            user.setName("user");
            user.setUsername("user");
            user.setPassword(passwordEncoder.encode("user"));
            user.getRoles().add("USER");
            userRepository.save(user);
        }
        System.out.println("Aplicação iniciada com sucesso!");
    }

}
