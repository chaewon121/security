package com.example.security1.google.repository;

// JpaRepository 를 상속하면 자동 컴포넌트 스캔됨.
//crud함수를 jparepository가 들고있음

import com.example.security1.google.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    // Jpa Naming 전략
    // SELECT * FROM user WHERE username = 1?
    UserEntity findByUsername(String username);
    // SELECT * FROM user WHERE username = 1? AND password = 2?
    // User findByUsernameAndPassword(String username, String password);

    UserEntity findById(Long id);


    // @Query(value = "select * from user", nativeQuery = true)
    // User find마음대로();
    // SELECT * FROM user WHERE provider = ?1 and providerId = ?2
    Optional<UserEntity> findByProviderAndProviderId(String provider, String providerId);
}