package com.gryphlabs.phoenix.api.auth.service;

public interface EmailDeliveryService {
    void sendRegistrationVerificationEmail(String recipientEmail, String displayName, String verificationLink);

    void sendPasswordChangeEmail(String recipientEmail, String displayName, String link);

    void sendPasswordResetEmail(String recipientEmail, String displayName, String link);

    void sendEmailChangeEmail(String recipientEmail, String displayName, String link);
}
