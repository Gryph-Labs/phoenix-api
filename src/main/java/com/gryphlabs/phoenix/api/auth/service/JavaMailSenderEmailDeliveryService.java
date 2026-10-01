package com.gryphlabs.phoenix.api.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailPreparationException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class JavaMailSenderEmailDeliveryService implements EmailDeliveryService {
    private final JavaMailSender mailSender;
    private final String senderAddress;

    public JavaMailSenderEmailDeliveryService(
            JavaMailSender mailSender,
            @Value("${PHOENIX_MAIL_USERNAME:}") String senderAddress) {
        this.mailSender = mailSender;
        this.senderAddress = senderAddress;
    }

    @Override
    public void sendRegistrationVerificationEmail(String recipientEmail, String displayName, String verificationLink) {
        MimeMessage message = mailSender.createMimeMessage();
        try {
            var helper = new MimeMessageHelper(message, false, "UTF-8");
            if (!senderAddress.isBlank()) {
                helper.setFrom(senderAddress);
            }

            helper.setTo(recipientEmail);
            helper.setSubject("Finish setting up your Phoenix account");
            helper.setText(content(displayName, verificationLink), false);
        } catch (MessagingException ex) {
            throw new MailPreparationException("Unable to prepare registration email.", ex);
        }
        mailSender.send(message);
    }

    @Override
    public void sendPasswordChangeEmail(String email, String name, String link) {
        send(
                email,
                "Change your Phoenix password",
                "Hello " + name + ",\n\nUse this link to change your password:\n\n" + link);
    }

    @Override
    public void sendPasswordResetEmail(String email, String name, String link) {
        send(
                email,
                "Reset your Phoenix password",
                "Hello " + name + ",\n\nUse this link to reset your password:\n\n" + link);
    }

    @Override
    public void sendEmailChangeEmail(String email, String name, String link) {
        send(
                email,
                "Confirm your Phoenix email change",
                "Hello " + name + ",\n\nConfirm your account email change using this link:\n\n" + link);
    }

    private void send(String email, String subject, String body) {
        MimeMessage message = mailSender.createMimeMessage();
        try {
            var helper = new MimeMessageHelper(message, false, "UTF-8");
            if (!senderAddress.isBlank()) {
                helper.setFrom(senderAddress);
            }

            helper.setTo(email);
            helper.setSubject(subject);
            helper.setText(body, false);
        } catch (MessagingException ex) {
            throw new MailPreparationException("Unable to prepare password email.", ex);
        }
        mailSender.send(message);
    }

    private @NonNull String content(String displayName, String verificationLink) {
        return "Hello " + displayName + ",\n\n"
                + "Your Phoenix account is almost ready. Use the link below to finish setting up your account:\n\n"
                + verificationLink + "\n\n"
                + "This link is single-use and expires after the configured registration period.\n\n"
                + "If you did not request this account, you can ignore this email.";
    }
}
