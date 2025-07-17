package com.authserver.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegistrationStartRequest {

    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Display name is required")
    private String displayName;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;
}