package com.authserver.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegistrationStartResponse {

    @JsonProperty("publicKey")
    private PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PublicKeyCredentialCreationOptions {
        private String challenge;
        private RelyingParty rp;
        private User user;
        private AuthenticatorSelectionCriteria authenticatorSelection;
        private String attestation;
        private String[] pubKeyCredParams;
        private String[] excludeCredentials;
        private Integer timeout;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RelyingParty {
        private String id;
        private String name;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class User {
        private String id;
        private String name;
        private String displayName;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthenticatorSelectionCriteria {
        private String authenticatorAttachment;
        private String residentKey;
        private String userVerification;
    }
}