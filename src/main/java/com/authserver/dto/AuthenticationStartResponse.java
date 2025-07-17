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
public class AuthenticationStartResponse {

    @JsonProperty("publicKey")
    private PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PublicKeyCredentialRequestOptions {
        private String challenge;
        private Integer timeout;
        private String rpId;
        private AllowCredential[] allowCredentials;
        private String userVerification;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AllowCredential {
        private String type;
        private String id;
        private String[] transports;
    }
}
