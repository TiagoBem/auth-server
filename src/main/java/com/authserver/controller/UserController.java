package com.authserver.controller;

import com.authserver.dto.UserResponse;
import com.authserver.dto.UserRoleUpdateRequest;
import com.authserver.entity.User;
import com.authserver.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @PutMapping("/{userId}/role")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<UserResponse> updateUserRole(@PathVariable Long userId, @Valid @RequestBody UserRoleUpdateRequest request) {
        return userService.updateUserRole(userId, request.getRole())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.badRequest().build());
    }
}