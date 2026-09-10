package com.gryphlabs.phoenix.api.auth.validation;

import com.gryphlabs.phoenix.api.config.PasswordProperties;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

import java.util.function.IntPredicate;

@Component
@RequiredArgsConstructor
public class PasswordValidator {
    private final PasswordProperties passwordProperties;

    public void validate(String password) {
        if (null == password || password.isBlank()) {
            throw new IllegalArgumentException("Password is required.");
        }

        if (password.length() < passwordProperties.minLength()) {
            throw new IllegalArgumentException("Password must be at least " +
                    passwordProperties.minLength() +
                    " characters.");
        }

        if (getCount(password, Character::isUpperCase) < passwordProperties.uppercase()) {
            throw new IllegalArgumentException("Password must contain at least " +
                    passwordProperties.uppercase() +
                    " uppercase character(s).");
        }

        if (getCount(password, Character::isLowerCase) < passwordProperties.lowercase()) {
            throw new IllegalArgumentException("Password must contain at least " +
                    passwordProperties.lowercase() +
                    " lowercase character(s).");
        }

        if (getCount(password, Character::isDigit) < passwordProperties.numbers()) {
            throw new IllegalArgumentException("Password must contain at least " +
                    passwordProperties.numbers() +
                    " number(s).");
        }

        if (password.chars().anyMatch(c -> !Character.isLetterOrDigit(c)
                && passwordProperties.specialCharacters().indexOf(c) < 0)) {
            throw new IllegalArgumentException("Password contains an unsupported character.");
        }

        if (getCount(password,
                c -> passwordProperties.specialCharacters().indexOf(c) >= 0) < passwordProperties.special()) {
            throw new IllegalArgumentException("Password must contain at least " +
                    passwordProperties.special() +
                    " special character(s).");
        }
    }

    private long getCount(@NonNull String password, @NonNull IntPredicate predicate) {
        return password.chars()
                .filter(predicate)
                .count();
    }
}
