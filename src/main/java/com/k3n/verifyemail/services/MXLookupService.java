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

    private final Set<String> disposableDomains;

    public MXLookupService(DisposableDomainConfig config) {
        this.disposableDomains = config.getDomainSet();
    }

    public String categorizeEmail(String email) {
        if (!isValidEmail(email)) return "Invalid";

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
        } catch (Exception e) {
            return "Unknown";
        }

        Boolean smtpValid = isSmtpValid(mxRecords, email);
        return smtpValid == null ? "Unknown" : smtpValid ? "Valid" : "Invalid";
    }

    public boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    public String extractDomain(String email) {
        int atIndex = email.indexOf('@');
        return (atIndex > 0) ? email.substring(atIndex + 1).toLowerCase(Locale.ROOT) : null;
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

        if (attr == null) return List.of();

        return IntStream.range(0, attr.size())
                .mapToObj(i -> {
                    try {
                        return attr.get(i).toString();
                    } catch (NamingException e) {
                        return "";
                    }
                })
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    public boolean isCatchAll(List<String> mxRecords, String domain) {
        String mxHost = extractMxHost(mxRecords.get(0));
        String fakeEmail = UUID.randomUUID().toString().replace("-", "").substring(0, 8) + "@" + domain;
        return Boolean.TRUE.equals(trySmtpRecipient(mxHost, fakeEmail));
    }

    public Boolean isSmtpValid(List<String> mxRecords, String email) {
        String mxHost = extractMxHost(mxRecords.get(0));
        return trySmtpRecipient(mxHost, email);
    }

    private Boolean trySmtpRecipient(String mxHost, String email) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(mxHost, 25), 3000);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            if (!readResponse(reader, "220")) return false;

            sendCommand(writer, "EHLO kaalb.in");
            if (!readResponse(reader, "250")) return false;

            sendCommand(writer, "MAIL FROM:<support@kaalb.in>");
            if (!readResponse(reader, "250")) return false;

            sendCommand(writer, "RCPT TO:<" + email + ">");
            String response = reader.readLine();
            if (response == null) return null;
            if (response.startsWith("250")) return true;
            if (response.startsWith("550")) return false;

            return null;
        } catch (IOException e) {
            return null;
        }
    }

    private void sendCommand(BufferedWriter writer, String command) throws IOException {
        writer.write(command + "\r\n");
        writer.flush();
    }

    private boolean readResponse(BufferedReader reader, String expectedPrefix) throws IOException {
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.startsWith(expectedPrefix)) return true;
            if (line.startsWith("5") || line.startsWith("4")) return false;
        }
        return false;
    }

    private String extractMxHost(String mxRecord) {
        String[] parts = mxRecord.split("\\s+");
        String host = parts.length >= 2 ? parts[1] : mxRecord;
        return host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
    }
}