package com.k3n.verifyemail.util;

import org.springframework.stereotype.Component;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketTimeoutException;

/**
 * Utility for validating SMTP recipients by issuing SMTP commands over raw sockets.
 * Performs EHLO, MAIL FROM and RCPT TO commands to verify recipient existence.
 */
@Component
public class SmtpRcptValidator {

    public enum SmtpRecipientStatus {
        Valid,
        UserNotFound,
        TemporaryFailure,
        UnknownFailure
    }

    public static class ValidationResult {
        private final SmtpRecipientStatus status;
        private final int smtpCode;
        private final String smtpResponse;
        private final String errorMessage;

        public ValidationResult(SmtpRecipientStatus status, int smtpCode, String smtpResponse, String errorMessage) {
            this.status = status;
            this.smtpCode = smtpCode;
            this.smtpResponse = smtpResponse;
            this.errorMessage = errorMessage;
        }

        public SmtpRecipientStatus getStatus() {
            return status;
        }

        public int getSmtpCode() {
            return smtpCode;
        }

        public String getSmtpResponse() {
            return smtpResponse;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    public ValidationResult validateRecipient(String mxHost, String email) {
        try (Socket socket = new Socket(mxHost, 25)) {
            socket.setSoTimeout(5000);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

            readResponse(reader); // Initial banner
            writer.println("EHLO example.com");
            readResponse(reader);

            writer.println("MAIL FROM:<check@example.com>");
            readResponse(reader);

            writer.println("RCPT TO:<" + email + ">");
            String response = reader.readLine();
            int code = parseSmtpCode(response);

            if (code == 250) {
                return new ValidationResult(SmtpRecipientStatus.Valid, code, response, null);
            } else if (code == 550) {
                return new ValidationResult(SmtpRecipientStatus.UserNotFound, code, response, null);
            } else if (code >= 400 && code < 500) {
                return new ValidationResult(SmtpRecipientStatus.TemporaryFailure, code, response, null);
            } else {
                return new ValidationResult(SmtpRecipientStatus.UnknownFailure, code, response, null);
            }

        } catch (SocketTimeoutException e) {
            return new ValidationResult(SmtpRecipientStatus.TemporaryFailure, -1, null, "Timeout: " + e.getMessage());
        } catch (Exception e) {
            return new ValidationResult(SmtpRecipientStatus.UnknownFailure, -1, null, "Error: " + e.getMessage());
        }
    }

    private void readResponse(BufferedReader reader) throws Exception {
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.length() < 4 || line.charAt(3) != '-') break;
        }
    }

    private int parseSmtpCode(String response) {
        if (response == null || response.length() < 3) return -1;
        try {
            return Integer.parseInt(response.substring(0, 3));
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}