package com.gryphlabs.phoenix.api.auth.service;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Test;
import org.springframework.mail.javamail.JavaMailSender;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JavaMailSenderEmailDeliveryServiceTest {
    @Test
    void sendsRegistrationEmailWithSetupLinkAndDisplayName() throws Exception {
        var mailSender = mock(JavaMailSender.class);
        var message = new MimeMessage(Session.getInstance(new Properties()));
        when(mailSender.createMimeMessage()).thenReturn(message);
        var service = new JavaMailSenderEmailDeliveryService(mailSender, "sender@example.com");

        service.sendRegistrationVerificationEmail(
                "person@example.com", "Mike", "http://localhost:8081/auth/register/confirm?token=raw-token");

        verify(mailSender).send(message);
        assertTrue(message.getRecipients(MimeMessage.RecipientType.TO)[0].toString().contains("person@example.com"));
        assertTrue(message.getSubject().contains("Phoenix"));
        assertTrue(message.getContent().toString().contains("Hello Mike"));
        assertTrue(message.getContent().toString().contains("token=raw-token"));
    }
}
