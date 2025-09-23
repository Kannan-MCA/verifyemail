package com.k3n.verifyemail.services;

import com.k3n.verifyemail.config.DisposableDomainConfig;
import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
public class MXLookupService {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$", Pattern.CASE_INSENSITIVE);

    private static final int SMTP_PORT = 25;
    private static final int SOCKET_TIMEOUT_MS = 3000;

    private final Set<String> disposableDomains;
    private final String ehloDomain;
    private final String mailFromAddress;

    public MXLookupService(DisposableDomainConfig config) {
        this.disposableDomains = config.getDomainSet();
        this.ehloDomain = "kaalb.in";         // configurable as needed
        this.mailFromAddress = "support@kaalb.in";  // configurable as needed
    }

    public String categorizeEmail(String email) {
        if (!isValidEmail(email)) {
            return "Invalid";
        }

        String domain = extractDomain(email);
        if (domain == null) return "Invalid";

        if (isDisposableDomain(domain)) return "Disposable";

        List<String> mxRecords;
        try {
            mxRecords = getMXRecords(domain);
        } catch (NamingException e) {
            return "Unknown";
        }

        if (mxRecords.isEmpty()) return "Invalid";

        try {
            if (isCatchAll(mxRecords, domain)) return "Catch-All";
        } catch (IOException e) {
            return "Unknown";
        }

        Integer smtpStatus = smtpCheckStatus(mxRecords, email);
        if (smtpStatus == null) return "Unknown";

        switch (smtpStatus) {
            case 1: // Valid user
                return "Valid";
            case 0: // User not found
                return "UserNotFound";
            case -1: // Invalid or rejected typically
                return "Invalid";
            default:
                return "Unknown";
        }
    }

    public boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    public String extractDomain(String email) {
        int atIndex = email.indexOf('@');
        return (atIndex > 0 && atIndex < email.length() - 1) ?
                email.substring(atIndex + 1).toLowerCase(Locale.ROOT) : null;
    }

    public boolean isDisposableDomain(String domain) {
        return disposableDomains.contains(domain);
    }

    public List<String> getMXRecords(String domain) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        DirContext ctx = new InitialDirContext(env);
        Attributes attrs = ctx.getAttributes(domain, new String[]{"MX"});
        Attribute attr = attrs.get("MX");

        if (attr == null) {
            return Collections.emptyList();
        }

        List<String> mxRecords = IntStream.range(0, attr.size())
                .mapToObj(i -> {
                    try {
                        return attr.get(i).toString();
                    } catch (NamingException e) {
                        return "";
                    }
                })
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());

        return mxRecords.stream()
                .sorted(Comparator.comparingInt(this::parsePriority))
                .collect(Collectors.toList());
    }

    private int parsePriority(String mxRecord) {
        String[] parts = mxRecord.split("\\s+");
        try {
            return Integer.parseInt(parts[0]);
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
            return Integer.MAX_VALUE;
        }
    }

    public boolean isCatchAll(List<String> mxRecords, String domain) throws IOException {
        String mxHost = extractMxHost(mxRecords.get(0));
        String fakeEmail = generateRandomLocalPart() + "@" + domain;
        Boolean catchAllResult = trySmtpRecipient(mxHost, fakeEmail);
        return Boolean.TRUE.equals(catchAllResult);
    }
    private Boolean trySmtpRecipient(String mxHost, String email) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(mxHost, SMTP_PORT), SOCKET_TIMEOUT_MS);
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            if (!readResponse(reader, "220")) return false;

            sendCommand(writer, "EHLO " + ehloDomain);
            if (!readResponse(reader, "250")) return false;

            sendCommand(writer, "MAIL FROM:<" + mailFromAddress + ">");
            if (!readResponse(reader, "250")) return false;

            sendCommand(writer, "RCPT TO:<" + email + ">");
            String response = reader.readLine();
            if (response == null) return null;

            response = response.toLowerCase(Locale.ROOT);

            if (response.startsWith("250")) return true;                  // Recipient accepted (valid)
            if (response.startsWith("550") || response.startsWith("553") ||
                    response.contains("recipient address rejected")) return false; // User not found / rejected

            if (response.startsWith("450") || response.startsWith("451") || response.startsWith("452")) {
                return null;                                              // Temporary failure - unknown
            }

            return null;  // Other responses inconclusive

        } catch (IOException e) {
            return null;  // Could not connect or error - unknown status
        }
    }


    /**
     * Checks SMTP status returning:
     * 1 for Valid
     * 0 for User not found
     * -1 for Invalid (other failures)
     * null for unknown/inconclusive
     */
    private Integer smtpCheckStatus(List<String> mxRecords, String email) {
        String mxHost = extractMxHost(mxRecords.get(0));
        return trySmtpRecipientWithStatus(mxHost, email);
    }

    private Integer trySmtpRecipientWithStatus(String mxHost, String email) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(mxHost, SMTP_PORT), SOCKET_TIMEOUT_MS);
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            if (!readResponse(reader, "220")) return -1;

            sendCommand(writer, "EHLO " + ehloDomain);
            if (!readResponse(reader, "250")) return -1;

            sendCommand(writer, "MAIL FROM:<" + mailFromAddress + ">");
            if (!readResponse(reader, "250")) return -1;

            sendCommand(writer, "RCPT TO:<" + email + ">");
            String response = reader.readLine();
            if (response == null) return null;

            response = response.toLowerCase(Locale.ROOT);

            if (response.startsWith("250")) return 1;           // Valid recipient
            if (response.startsWith("550")) return 0;           // User not found
            if (response.startsWith("553") || response.contains("recipient address rejected")) return 0;

            if (response.startsWith("450") || response.startsWith("451") ||
                    response.startsWith("452") || response.startsWith("4")) return null; // Temporary failure

            // For all other responses treat as invalid or unknown
            return -1;

        } catch (IOException e) {
            return null; // Unknown due to network/error issues
        }
    }

    private void sendCommand(BufferedWriter writer, String command) throws IOException {
        writer.write(command);
        writer.write("\r\n");
        writer.flush();
    }

    private boolean readResponse(BufferedReader reader, String expectedPrefix) throws IOException {
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.startsWith(expectedPrefix)) {
                // Check if multiline SMTP response (hyphen after code)
                if (line.length() > 3 && line.charAt(3) == '-') continue;
                return true;
            }
            if (line.startsWith("4") || line.startsWith("5")) {
                return false;
            }
        }
        return false;
    }

    private String extractMxHost(String mxRecord) {
        String[] parts = mxRecord.split("\\s+");
        String host = parts.length >= 2 ? parts[1] : mxRecord;
        return host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
    }

    private String generateRandomLocalPart() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    }
}
