package com.spring.SecurityMVC.SignUpInfo.Service;

import com.spring.SecurityMVC.SpringSecurity.ExceptionHandler.CustomExceptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

import java.util.Random;

@Service
@Slf4j
public class EmailService {

    @Value("${spring.mail.from}")
    private String fromEmail;

    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendEmail(String to, String subject, String body) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);

            mailSender.send(message);
            log.info("Email sent successfully to {}", to);
        } catch (Exception e) {
            log.error("Failed to send email to {}: {}", to, e.getMessage(), e);
            throw new CustomExceptions.EmailServiceException("Failed to send email to " + to, e);
        }
    }

    public String generateAuthCode() {
        Random random = new Random();
        int authCode = 100000 + random.nextInt(900000);
        return String.valueOf(authCode);
    }

}
