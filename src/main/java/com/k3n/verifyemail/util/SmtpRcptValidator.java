package com.k3n.verifyemail.util;

import com.sun.mail.smtp.SMTPTransport;
import jakarta.mail.Session;

import java.util.Properties;

public class SmtpRcptValidator {

    public enum SmtpRecipientStatus {
        Valid, UserNotFound, TemporaryFailure, UnknownFailure
    }

    public SmtpRecipientStatus validateRecipient(String mxHost, String email) {
        Properties props = new Properties();
        props.put("mail.smtp.host", mxHost);
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.connectiontimeout", "5000");
        props.put("mail.smtp.timeout", "5000");

        Session session = Session.getInstance(props, null);
        session.setDebug(false); // Set true for verbose SMTP logs

        try (SMTPTransport transport = (SMTPTransport) session.getTransport("smtp")) {
            transport.connect();

            // Issue EHLO
            transport.issueCommand("EHLO " + mxHost, 250);

            // Issue MAIL FROM
            transport.issueCommand("MAIL FROM:<validator@" + mxHost + ">", 250);

            // Issue RCPT TO
            try {
                transport.issueCommand("RCPT TO:<" + email + ">", 250);
                return SmtpRecipientStatus.Valid;
            } catch (jakarta.mail.MessagingException e) {
                String response = transport.getLastServerResponse();
                if (response == null) return SmtpRecipientStatus.UnknownFailure;

                response = response.toLowerCase();
                if (response.startsWith("550") || response.contains("user not found") || response.contains("recipient address rejected"))
                    return SmtpRecipientStatus.UserNotFound;
                if (response.startsWith("450") || response.startsWith("451") || response.startsWith("452") || response.startsWith("4"))
                    return SmtpRecipientStatus.TemporaryFailure;

                return SmtpRecipientStatus.UnknownFailure;
            }

        } catch (Exception e) {
            return SmtpRecipientStatus.TemporaryFailure;
        }
    }
}