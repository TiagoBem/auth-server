package com.authserver.service;

import com.authserver.dto.UserResponse;
import com.authserver.entity.Role;
import com.authserver.entity.User;
import com.authserver.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public Optional<UserResponse> updateUserRole(Long userId, Role newRole) {
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        Optional<User> currentUserOpt = userRepository.findByUsername(currentUsername);
        Optional<User> userToUpdateOpt = userRepository.findById(userId);

        if (currentUserOpt.isPresent() && userToUpdateOpt.isPresent()) {
            User currentUser = currentUserOpt.get();
            User userToUpdate = userToUpdateOpt.get();

            if (currentUser.getRole() == Role.ADMIN && !currentUser.getId().equals(userToUpdate.getId())) {
                userToUpdate.setRole(newRole);
                User updatedUser = userRepository.save(userToUpdate);
                return Optional.of(UserResponse.builder()
                        .id(updatedUser.getId())
                        .username(updatedUser.getUsername())
                        .role(updatedUser.getRole())
                        .build());
            }
        }
        return Optional.empty();
    }
}