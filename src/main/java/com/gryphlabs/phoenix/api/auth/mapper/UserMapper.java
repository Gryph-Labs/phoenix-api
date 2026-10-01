package com.gryphlabs.phoenix.api.auth.mapper;

import com.gryphlabs.phoenix.api.entity.PendingRegistration;
import com.gryphlabs.phoenix.api.entity.Role;
import com.gryphlabs.phoenix.api.entity.User;
import com.gryphlabs.phoenix.api.entity.UserStatus;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {
    @NonNull
    public User mapPendingRegistrationToUser(
            @NonNull PendingRegistration pendingRegistration,
            @NonNull String encodedPassword) {
        var user = new User();
        user.setEmail(pendingRegistration.getEmail());
        user.setDisplayName(pendingRegistration.getDisplayName());
        user.setPassword(encodedPassword);
        user.setRole(Role.USER);
        user.setStatus(UserStatus.ACTIVE);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);
        return user;
    }
}
