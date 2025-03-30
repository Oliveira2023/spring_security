package dev.oliveira.jwt_security.repository;

import dev.oliveira.jwt_security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Integer> {

    @Query("SELECT u FROM User u JOIN FETCH u.roles WHERE u.username = :username")
    public User findByUsername(@Param("username") String username);

    boolean existsByUsername(String username);
}
