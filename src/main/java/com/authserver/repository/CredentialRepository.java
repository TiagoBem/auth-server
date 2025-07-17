package com.authserver.repository;

import com.authserver.entity.Credential;
import com.authserver.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, Long> {
    Optional<Credential> findByCredentialId(String credentialId);
    List<Credential> findAllByUser(User user);
    boolean existsByCredentialId(String credentialId);
}
