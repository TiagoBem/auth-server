package com.authserver.controller;

import com.authserver.dto.AuthenticationRequest;
import com.authserver.dto.AuthenticationResponse;
import com.authserver.dto.UserResponse;
import com.authserver.entity.User;
import com.authserver.repository.UserRepository;
import com.authserver.service.WebAuthnUserDetailsService;
import com.authserver.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final WebAuthnUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        }
        catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password", e);
        }

        final User user = userRepository.findByUsername(authenticationRequest.getUsername()).orElseThrow(() -> new Exception("User not found"));

        final String jwt = jwtUtil.generateToken(user);

        return ResponseEntity.ok(AuthenticationResponse.builder()
                .access_token(jwt)
                .token_type("bearer")
                .expires_in(3600L)
                .user(new UserResponse(user.getId(), user.getUsername(), user.getRole()))
                .build());
    }

}
