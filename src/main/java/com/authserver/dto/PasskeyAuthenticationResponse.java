package com.authserver.dto;

import com.authserver.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasskeyAuthenticationResponse {
    private String access_token;
    private String username;
    private Role role;
}
