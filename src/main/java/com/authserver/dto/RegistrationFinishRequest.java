package com.authserver.dto;

import com.authserver.util.Base64UrlDeserializer;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegistrationFinishRequest {

    @JsonDeserialize(using = Base64UrlDeserializer.class)
    private String id;

    @JsonDeserialize(using = Base64UrlDeserializer.class)
    private String rawId;

    private String type;
    private Response response;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Response {
        @JsonDeserialize(using = Base64UrlDeserializer.class)
        private String attestationObject;

        @JsonDeserialize(using = Base64UrlDeserializer.class)
        private String clientDataJSON;

        @JsonProperty("transports")
        private String[] transports;
    }
}
