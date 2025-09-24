package com.k3n.verifyemail.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class SmtpRcptValidator {

    @Value("${smtp.timeout.ms:5000}")
    private int timeoutMs;

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
        private final String mxHost;
        private final String fullTranscript;
        private final String timestamp;
        private final String diagnosticTag;

        public ValidationResult(SmtpRecipientStatus status, int smtpCode, String smtpResponse,
                                String errorMessage, String mxHost, String fullTranscript,
                                String timestamp, String diagnosticTag) {
            this.status = status;
            this.smtpCode = smtpCode;
            this.smtpResponse = smtpResponse;
            this.errorMessage = errorMessage;
            this.mxHost = mxHost;
            this.fullTranscript = fullTranscript;
            this.timestamp = timestamp;
            this.diagnosticTag = diagnosticTag;
        }

        public SmtpRecipientStatus getStatus() { return status; }
        public int getSmtpCode() { return smtpCode; }
        public String getSmtpResponse() { return smtpResponse; }
        public String getErrorMessage() { return errorMessage; }
        public String getMxHost() { return mxHost; }
        public String getFullTranscript() { return fullTranscript; }
        public String getTimestamp() { return timestamp; }
        public String getDiagnosticTag() { return diagnosticTag; }
    }

    public ValidationResult validateRecipient(String mxHost, String email) {
        StringBuilder transcript = new StringBuilder();
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        try (Socket socket = new Socket(mxHost, 25)) {
            socket.setSoTimeout(timeoutMs);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

            transcript.append(readAndLog(reader)).append("\n");
            transcript.append(sendAndLog("EHLO example.com", reader, writer)).append("\n");
            transcript.append(sendAndLog("MAIL FROM:<knnnbca@gmail.com>", reader, writer)).append("\n");
            String rcptResponse = sendAndLog("RCPT TO:<" + email + ">", reader, writer);
            transcript.append(rcptResponse).append("\n");

            int code = parseSmtpCode(rcptResponse);
            SmtpRecipientStatus status = classifyResponse(code, rcptResponse);
            String tag = generateDiagnosticTag(code, rcptResponse);

            return new ValidationResult(status, code, rcptResponse, null, mxHost,
                    transcript.toString().trim(), timestamp, tag);

        } catch (SocketTimeoutException e) {
            return new ValidationResult(SmtpRecipientStatus.TemporaryFailure, -1, null,
                    "Timeout: " + e.getMessage(), mxHost, transcript.toString().trim(),
                    timestamp, "Timeout");
        } catch (Exception e) {
            return new ValidationResult(SmtpRecipientStatus.UnknownFailure, -1, null,
                    "Error: " + e.getMessage(), mxHost, transcript.toString().trim(),
                    timestamp, "Exception");
        }
    }

    private String sendAndLog(String command, BufferedReader reader, PrintWriter writer) throws Exception {
        writer.println(command);
        String response = readFullResponse(reader);
        return ">> " + command + "\n<< " + response;
    }

    private String readAndLog(BufferedReader reader) throws Exception {
        String response = readFullResponse(reader);
        return "<< " + response;
    }

    private String readFullResponse(BufferedReader reader) throws Exception {
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line).append("\n");
            if (line.length() < 4 || line.charAt(3) != '-') break;
        }
        return response.toString().trim();
    }

    private int parseSmtpCode(String response) {
        if (response == null || response.length() < 3) return -1;
        String[] lines = response.split("\n");
        String lastLine = lines[lines.length - 1].trim();

        // Remove transcript prefix if present
        if (lastLine.startsWith("<< ")) {
            lastLine = lastLine.substring(3).trim();
        }

        System.out.println("Parsing SMTP code from: " + lastLine);

        if (lastLine.length() < 3) return -1;

        try {
            return Integer.parseInt(lastLine.substring(0, 3));
        } catch (NumberFormatException e) {
            System.out.println("Failed to parse SMTP code: " + e.getMessage());
            return -1;
        }
    }


    private SmtpRecipientStatus classifyResponse(int code, String response) {
        String lower = response != null ? response.toLowerCase() : "";

        if (code >= 250 && code <= 259) return SmtpRecipientStatus.Valid;
        if (code == 252 || (code >= 400 && code < 500)) return SmtpRecipientStatus.TemporaryFailure;
        if (code == 550 || code == 551 || code == 553 || lower.contains("user not found")) return SmtpRecipientStatus.UserNotFound;
        if (code == 554 || lower.contains("relay access denied") || lower.contains("not permitted")) return SmtpRecipientStatus.UnknownFailure;
        if (code >= 500 && code < 600) return SmtpRecipientStatus.UnknownFailure;

        return SmtpRecipientStatus.UnknownFailure;
    }

    private String generateDiagnosticTag(int code, String response) {
        String lower = response != null ? response.toLowerCase() : "";

        if (code == 250) return "Accepted";
        if (code == 251) return "Forwarded";
        if (code == 252) return "CannotVerify";
        if (code == 421) return "ServiceUnavailable";
        if (code == 450) return "MailboxBusy";
        if (code == 451) return "LocalError";
        if (code == 452) return "InsufficientStorage";
        if (code == 550) return "MailboxNotFound";
        if (code == 551) return "UserNotLocal";
        if (code == 552) return "StorageExceeded";
        if (code == 553) return "MailboxNameInvalid";
        if (code == 554) return "TransactionFailed";
        if (lower.contains("relay access denied")) return "RelayDenied";
        if (lower.contains("not permitted")) return "AccessDenied";
        if (lower.contains("greylist")) return "Greylisted";
        if (lower.contains("syntax")) return "SyntaxError";

        return "Unclassified";
    }
}