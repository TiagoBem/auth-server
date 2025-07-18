package com.authserver.dto;

import com.authserver.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {
    private String access_token;
    private Long id;
    private String username;
    private Role role;
}