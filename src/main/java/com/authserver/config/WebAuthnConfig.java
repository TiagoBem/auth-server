package com.authserver.config;

import com.authserver.dto.RegistrationStartResponse;
import com.authserver.service.WebAuthnCredentialRepository;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserVerificationRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
@RequiredArgsConstructor
public class WebAuthnConfig {

    private static final String RP_ID = "localhost";
    private static final String RP_NAME = "WebAuthn Demo";
    private static final Set<String> RP_ORIGINS = Set.of("http://localhost:8080");

    private final WebAuthnCredentialRepository webAuthnCredentialRepository;

    @Bean
    public RelyingPartyIdentity relyingPartyIdentity() {
        return RelyingPartyIdentity.builder()
                .id(RP_ID)
                .name(RP_NAME)
                .build();
    }

    @Bean
    public RegistrationStartResponse.AuthenticatorSelectionCriteria authenticatorSelectionCriteria() {
        return RegistrationStartResponse.AuthenticatorSelectionCriteria.builder()
                // Remove the authenticatorAttachment restriction to allow both platform and cross-platform authenticators
                .residentKey(ResidentKeyRequirement.PREFERRED)
                .userVerification(UserVerificationRequirement.PREFERRED)
                .build();
    }

    @Bean
    public RegistrationStartResponse.RelyingParty relyingParty() {
        return RegistrationStartResponse.RelyingParty.builder()
                .identity(relyingPartyIdentity())
                .credentialRepository(webAuthnCredentialRepository)
                .origins(RP_ORIGINS)
                .attestationConveyancePreference(AttestationConveyancePreference.DIRECT)
                .allowUntrustedAttestation(true)
                .build();
    }
}
