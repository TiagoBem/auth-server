package com.authserver.controller;

import com.authserver.dto.*;
import com.authserver.entity.Credential;
import com.authserver.entity.RefreshToken;
import com.authserver.entity.User;
import com.authserver.repository.CredentialRepository;
import com.authserver.repository.UserRepository;
import com.authserver.service.RefreshTokenService;
import com.authserver.util.JwtUtil;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

@RestController
@RequestMapping("/login")
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

    private final RelyingParty relyingParty;
    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    @Value("${jwt.access-token.expiration}")
    private Long accessTokenExpiration;

    @PostMapping("/start")
    public ResponseEntity<AuthenticationStartResponse> startAuthentication(
            @Valid @RequestBody AuthenticationStartRequest request,
            HttpSession session) {

        Optional<User> userOpt = userRepository.findByUsername(request.getUsername());
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest()
                    .header("X-Authentication-Error", "User not found")
                    .build();
        }

        StartAssertionOptions options = StartAssertionOptions.builder()
                .username(request.getUsername())
                .build();

        AssertionRequest assertionRequest = relyingParty.startAssertion(options);

        // Store in session
        session.setAttribute("assertionRequest", assertionRequest);
        session.setAttribute("username", request.getUsername());

        // Create a simplified response
        AuthenticationStartResponse.PublicKeyCredentialRequestOptions requestOptions =
                AuthenticationStartResponse.PublicKeyCredentialRequestOptions.builder()
                        .challenge(assertionRequest.getPublicKeyCredentialRequestOptions().getChallenge().getBase64Url())
                        .rpId(assertionRequest.getPublicKeyCredentialRequestOptions().getRpId())
                        .timeout(60000)
                        .userVerification("preferred")
                        .allowCredentials(new AuthenticationStartResponse.AllowCredential[0])
                        .build();

        AuthenticationStartResponse response = AuthenticationStartResponse.builder()
                .publicKeyCredentialRequestOptions(requestOptions)
                .build();

        return ResponseEntity.ok(response);
    }

    @PostMapping("/finish")
    public ResponseEntity<PasskeyAuthenticationResponse> finishAuthentication(
            @RequestBody AuthenticationFinishRequest request,
            HttpSession session) {

        try {
            // Get stored data from session
            AssertionRequest assertionRequest = (AssertionRequest) session.getAttribute("assertionRequest");
            String username = (String) session.getAttribute("username");

            if (assertionRequest == null || username == null) {
                return ResponseEntity.badRequest()
                        .header("X-Authentication-Error", "Authentication session expired or invalid")
                        .build();
            }

            // Parse client response
            ByteArray authenticatorData;
            ByteArray clientDataJSON;
            ByteArray credentialId;
            ByteArray signature;

            try {
                authenticatorData = ByteArray.fromBase64Url(request.getResponse().getAuthenticatorData());
                clientDataJSON = ByteArray.fromBase64Url(request.getResponse().getClientDataJSON());
                credentialId = ByteArray.fromBase64Url(request.getId());
                signature = ByteArray.fromBase64Url(request.getResponse().getSignature());
            } catch (Base64UrlException e) {
                log.error("Failed to decode Base64URL", e);
                return ResponseEntity.badRequest()
                        .header("X-Authentication-Error", "Invalid Base64URL encoding: " + e.getMessage())
                        .build();
            }

            AuthenticatorAssertionResponse assertionResponse;
            try {
                assertionResponse = AuthenticatorAssertionResponse.builder()
                        .authenticatorData(authenticatorData)
                        .clientDataJSON(clientDataJSON)
                        .signature(signature)
                        .build();
            } catch (Exception e) {
                log.error("Failed to build assertion response", e);
                return ResponseEntity.badRequest()
                        .header("X-Authentication-Error", "Failed to process authentication data: " + e.getMessage())
                        .build();
            }

            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                    PublicKeyCredential.<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>builder()
                            .id(credentialId)
                            .response(assertionResponse)
                            .clientExtensionResults(ClientAssertionExtensionOutputs.builder().build())
                            .build();

            // Finish authentication
            FinishAssertionOptions finishOptions = FinishAssertionOptions.builder()
                    .request(assertionRequest)
                    .response(pkc)
                    .build();

            AssertionResult result = relyingParty.finishAssertion(finishOptions);

            if (result.isSuccess()) {
                User user = userRepository.findByUsername(username).orElseThrow();

                // Update credential
                Optional<Credential> credentialOpt = credentialRepository.findByCredentialId(result.getCredentialId().getBase64Url());
                if (credentialOpt.isPresent()) {
                    Credential credential = credentialOpt.get();
                    credential.setSignatureCount(result.getSignatureCount());
                    credential.setLastUsedTime(Instant.now());
                    credentialRepository.save(credential);
                }

                // Authenticate user
                Collection<GrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority(user.getRole().name()));
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        authorities
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Clear session
                session.removeAttribute("assertionRequest");
                session.removeAttribute("username");

                final String jwt = jwtUtil.generateToken(user);
                final RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

                return ResponseEntity.ok(PasskeyAuthenticationResponse.builder()
                        .access_token(jwt)
                        .refresh_token(refreshToken.getToken())
                        .token_type("bearer")
                        .expires_in(accessTokenExpiration / 1000L)
                        .user(new UserResponse(user.getId(), user.getUsername(), user.getRole()))
                        .build());
            } else {
                return ResponseEntity.badRequest()
                        .header("X-Authentication-Error", "Authentication verification failed")
                        .build();
            }
        } catch (AssertionFailedException e) {
            log.error("Authentication failed", e);
            return ResponseEntity.badRequest()
                    .header("X-Authentication-Error", e.getMessage())
                    .build();
        } catch (Exception e) {
            log.error("Unexpected error during authentication", e);
            return ResponseEntity.badRequest()
                    .header("X-Authentication-Error", "Unexpected error: " + e.getMessage())
                    .build();
        }
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtil.generateToken(user);
                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                })
                .orElseThrow(() -> new RuntimeException("Refresh token is not in database!"));
    }
}
