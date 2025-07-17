package com.authserver.controller;

import com.authserver.dto.RegistrationFinishRequest;
import com.authserver.dto.RegistrationStartRequest;
import com.authserver.dto.RegistrationStartResponse;
import com.authserver.entity.Credential;
import com.authserver.entity.User;
import com.authserver.repository.CredentialRepository;
import com.authserver.repository.UserRepository;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequestMapping("/register")
@RequiredArgsConstructor
@Slf4j
public class RegistrationController {

    private final RelyingParty relyingParty;
    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;

    @PostMapping("/start")
    public ResponseEntity<RegistrationStartResponse> startRegistration(
            @Valid @RequestBody RegistrationStartRequest request,
            HttpSession session) {

        // Check if username or email already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            return ResponseEntity.badRequest()
                    .header("X-Registration-Error", "Username already exists")
                    .build();
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest()
                    .header("X-Registration-Error", "Email already exists")
                    .build();
        }

        // Create user identity
        UserIdentity userIdentity = UserIdentity.builder()
                .name(request.getUsername())
                .displayName(request.getDisplayName())
                .id(new ByteArray(request.getUsername().getBytes()))
                .build();

        // Start registration
        StartRegistrationOptions options = StartRegistrationOptions.builder()
                .user(userIdentity)
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                .residentKey(com.yubico.webauthn.data.ResidentKeyRequirement.PREFERRED)
                .userVerification(com.yubico.webauthn.data.UserVerificationRequirement.PREFERRED)
                .build())
                .build();

        PublicKeyCredentialCreationOptions creationOptions = relyingParty.startRegistration(options);

        // Store in session
        session.setAttribute("creationOptions", creationOptions);
        session.setAttribute("username", request.getUsername());
        session.setAttribute("displayName", request.getDisplayName());
        session.setAttribute("email", request.getEmail());

        // Convert to response
        RegistrationStartResponse response = convertToRegistrationStartResponse(creationOptions);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/finish")
    public ResponseEntity<Void> finishRegistration(
            @RequestBody RegistrationFinishRequest request,
            HttpSession session) {

        try {
            // Get stored data from session
            PublicKeyCredentialCreationOptions creationOptions =
                    (PublicKeyCredentialCreationOptions) session.getAttribute("creationOptions");
            String username = (String) session.getAttribute("username");
            String displayName = (String) session.getAttribute("displayName");
            String email = (String) session.getAttribute("email");

            if (creationOptions == null || username == null || displayName == null || email == null) {
                return ResponseEntity.badRequest()
                        .header("X-Registration-Error", "Registration session expired or invalid")
                        .build();
            }

            // Parse client response
            ByteArray attestationObject;
            ByteArray clientDataJSON;
            ByteArray credentialId;

            try {
                attestationObject = ByteArray.fromBase64Url(request.getResponse().getAttestationObject());
                clientDataJSON = ByteArray.fromBase64Url(request.getResponse().getClientDataJSON());
                credentialId = ByteArray.fromBase64Url(request.getId());
            } catch (Base64UrlException e) {
                log.error("Failed to decode Base64URL", e);
                return ResponseEntity.badRequest()
                        .header("X-Registration-Error", "Invalid Base64URL encoding: " + e.getMessage())
                        .build();
            }

            AuthenticatorAttestationResponse attestation;
            try {
                attestation = AuthenticatorAttestationResponse.builder()
                        .attestationObject(attestationObject)
                        .clientDataJSON(clientDataJSON)
                        .build();
            } catch (Exception e) {
                log.error("Failed to build attestation response", e);
                return ResponseEntity.badRequest()
                        .header("X-Registration-Error", "Failed to process registration data: " + e.getMessage())
                        .build();
            }

            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                    PublicKeyCredential.<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
                            .id(credentialId)
                            .response(attestation)
                            .clientExtensionResults(ClientRegistrationExtensionOutputs.builder().build())
                            .build();

            // Finish registration
            FinishRegistrationOptions finishOptions = FinishRegistrationOptions.builder()
                    .request(creationOptions)
                    .response(pkc)
                    .build();

            RegistrationResult result = relyingParty.finishRegistration(finishOptions);

            // Create user
            User user = User.builder()
                    .username(username)
                    .displayName(displayName)
                    .email(email)
                    .build();
            userRepository.save(user);

            // Create credential
            Credential credential = Credential.builder()
                    .credentialId(result.getKeyId().getId().getBase64Url())
                    .publicKey(result.getPublicKeyCose().getBase64Url())
                    .user(user)
                    .aaguid("") // Simplified to avoid issues
                    .signatureCount(result.getSignatureCount())
                    .registrationTime(Instant.now())
                    .lastUsedTime(Instant.now())
                    .build();
            credentialRepository.save(credential);

            // Clear session
            session.removeAttribute("creationOptions");
            session.removeAttribute("username");
            session.removeAttribute("displayName");
            session.removeAttribute("email");

            return ResponseEntity.ok().build();
        } catch (RegistrationFailedException e) {
            log.error("Registration failed", e);
            return ResponseEntity.badRequest()
                    .header("X-Registration-Error", e.getMessage())
                    .build();
        } catch (Exception e) {
            log.error("Unexpected error during registration", e);
            return ResponseEntity.badRequest()
                    .header("X-Registration-Error", "Unexpected error: " + e.getMessage())
                    .build();
        }
    }

    private RegistrationStartResponse convertToRegistrationStartResponse(
            PublicKeyCredentialCreationOptions creationOptions) {

        RegistrationStartResponse.PublicKeyCredentialCreationOptions options =
                RegistrationStartResponse.PublicKeyCredentialCreationOptions.builder()
                        .challenge(creationOptions.getChallenge().getBase64Url())
                        .rp(RegistrationStartResponse.RelyingParty.builder()
                                .id(creationOptions.getRp().getId())
                                .name(creationOptions.getRp().getName())
                                .build())
                        .user(RegistrationStartResponse.User.builder()
                                .id(creationOptions.getUser().getId().getBase64Url())
                                .name(creationOptions.getUser().getName())
                                .displayName(creationOptions.getUser().getDisplayName())
                                .build())
                        .authenticatorSelection(RegistrationStartResponse.AuthenticatorSelectionCriteria.builder()
                                .authenticatorAttachment(creationOptions.getAuthenticatorSelection()
                                        .map(as -> as.getAuthenticatorAttachment().map(Object::toString).orElse(null))
                                        .orElse(null))
                                .residentKey(creationOptions.getAuthenticatorSelection()
                                        .map(as -> as.getResidentKey().get())
                                        .orElse(null))
                                .userVerification(creationOptions.getAuthenticatorSelection()
                                        .map(as -> as.getUserVerification().toString())
                                        .orElse(null))
                                .build())
                        .attestation(creationOptions.getAttestation().toString())
                        .pubKeyCredParams(creationOptions.getPubKeyCredParams().stream()
                                .map(param -> param.getAlg().toString())
                                .toArray(String[]::new))
                        .timeout(creationOptions.getTimeout().map(Long::intValue).orElse(null))
                        .build();

        return RegistrationStartResponse.builder()
                .publicKeyCredentialCreationOptions(options)
                .build();
    }
}