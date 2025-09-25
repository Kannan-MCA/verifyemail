package com.k3n.verifyemail.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Component
public class SmtpRcptValidator {

    @Value("${smtp.timeout.ms:5000}")
    private int timeoutMs;

    public enum SmtpRecipientStatus {
        Valid,
        UserNotFound,
        TemporaryFailure,
        UnknownFailure,
        Blacklisted
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
            String ehloResponse = sendAndLog("EHLO gmail.com", reader, writer);
            transcript.append(ehloResponse).append("\n");

            if (ehloResponse.toLowerCase().contains("starttls")) {
                transcript.append(sendAndLog("STARTTLS", reader, writer)).append("\n");

                try {
                    Socket tlsSocket = upgradeToTls(socket, mxHost);
                    reader = new BufferedReader(new InputStreamReader(tlsSocket.getInputStream()));
                    writer = new PrintWriter(tlsSocket.getOutputStream(), true);

                    SSLSocket sslSocket = (SSLSocket) tlsSocket;
                    transcript.append("<< TLS handshake successful\n");
                    transcript.append("<< TLS protocol: ").append(sslSocket.getSession().getProtocol()).append("\n");
                    transcript.append("<< TLS cipher suite: ").append(sslSocket.getSession().getCipherSuite()).append("\n");
                    transcript.append(sendAndLog("EHLO gmail.com", reader, writer)).append("\n");

                } catch (Exception tlsEx) {
                    transcript.append("<< TLS handshake failed: ").append(tlsEx.getMessage()).append("\n");
                    return new ValidationResult(SmtpRecipientStatus.TemporaryFailure, -1, null,
                            "TLS handshake failed", mxHost, transcript.toString().trim(),
                            timestamp, "TLSHandshakeFailed");
                }
            } else {
                transcript.append(">> STARTTLS not supported by server\n");
            }

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

    public boolean isCatchAll(List<String> mxHosts, String domain) {
        String testEmail = "nonexistent-" + System.currentTimeMillis() + "@" + domain;

        for (String mxHost : mxHosts) {
            ValidationResult result = validateRecipient(mxHost, testEmail);
            if (result.getStatus() == SmtpRecipientStatus.Valid &&
                    result.getSmtpCode() == 250 &&
                    "Accepted".equals(result.getDiagnosticTag())) {
                return true;
            }
        }

        return false;
    }

    private Socket upgradeToTls(Socket plainSocket, String mxHost) throws Exception {
        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(
                plainSocket, mxHost, plainSocket.getPort(), true);
        sslSocket.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
        sslSocket.startHandshake();
        return sslSocket;
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
        if (lastLine.startsWith("<< ")) lastLine = lastLine.substring(3).trim();
        try {
            return Integer.parseInt(lastLine.substring(0, 3));
        } catch (NumberFormatException e) {
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
        if (code == 550 && (lower.contains("blocked") || lower.contains("spamhaus") || lower.contains("blacklist"))) return SmtpRecipientStatus.Blacklisted;

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
        if (code == 550) return "UserNotFound";
        if (code == 551) return "UserNotLocal";
        if (code == 552) return "StorageExceeded";
        if (lower.contains("relay access denied")) return "RelayDenied";
        if (lower.contains("not permitted")) return "AccessDenied";
        if (lower.contains("spamhaus") || lower.contains("blocked using") || lower.contains("blacklist")) return "BlockedByBlacklist";
        return "Unclassified";
    }
}