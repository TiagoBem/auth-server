package com.authserver.service;

import com.authserver.entity.User;
import com.authserver.repository.CredentialRepository;
import com.authserver.repository.UserRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.exception.Base64UrlException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class WebAuthnCredentialRepository implements com.yubico.webauthn.CredentialRepository {

    private final CredentialRepository credentialRepository;
    private final UserRepository userRepository;

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> credentialRepository.findAllByUser(user).stream()
                        .map(credential -> {
                            try {
                                return PublicKeyCredentialDescriptor.builder()
                                        .id(ByteArray.fromBase64Url(credential.getCredentialId()))
                                        .build();
                            } catch (Base64UrlException e) {
                                log.error("Failed to decode credential ID: {}", credential.getCredentialId(), e);
                                return null;
                            }
                        })
                        .filter(descriptor -> descriptor != null)
                        .collect(Collectors.toSet()))
                .orElse(Set.of());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return userRepository.findByUsername(username)
                .map(user -> new ByteArray(user.getId().toString().getBytes()));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        String userHandleString = new String(userHandle.getBytes());
        try {
            Long userId = Long.parseLong(userHandleString);
            return userRepository.findById(userId).map(User::getUsername);
        } catch (NumberFormatException e) {
            log.error("Failed to parse user handle: {}", userHandleString, e);
            return Optional.empty();
        }
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        String credentialIdString = credentialId.getBase64Url();
        return credentialRepository.findByCredentialId(credentialIdString)
                .map(credential -> {
                    try {
                        return RegisteredCredential.builder()
                                .credentialId(credentialId)
                                .userHandle(userHandle)
                                .publicKeyCose(ByteArray.fromBase64Url(credential.getPublicKey()))
                                .signatureCount(credential.getSignatureCount())
                                .build();
                    } catch (Exception e) {
                        log.error("Failed to decode public key: {}", credential.getPublicKey(), e);
                        return null;
                    }
                });
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        String credentialIdString = credentialId.getBase64Url();
        return credentialRepository.findByCredentialId(credentialIdString)
                .map(credential -> {
                    ByteArray userHandle = new ByteArray(credential.getUser().getId().toString().getBytes());
                    try {
                        return Set.of(RegisteredCredential.builder()
                                .credentialId(credentialId)
                                .userHandle(userHandle)
                                .publicKeyCose(ByteArray.fromBase64Url(credential.getPublicKey()))
                                .signatureCount(credential.getSignatureCount())
                                .build());
                    } catch (Exception e) {
                        log.error("Failed to decode public key: {}", credential.getPublicKey(), e);
                        return Set.<RegisteredCredential>of();
                    }
                })
                .orElse(Set.of());
    }
}