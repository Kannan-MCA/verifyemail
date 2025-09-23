package com.k3n.verifyemail.services;

import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
public class MXLookupService  {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$", Pattern.CASE_INSENSITIVE);

    private static final Set<String> DISPOSABLE_DOMAINS = Set.of(
            "mailinator.com", "10minutemail.com", "tempmail.com", "guerrillamail.com"
    );

    public String categorizeEmail(String email) {
        if (!isValidEmail(email))
            return "Invalid";

        String domain = extractDomain(email);
        if (domain == null) return "Invalid";

        if (isDisposableDomain(domain))
            return "Disposable";

        List<String> mxRecords;
        try {
            mxRecords = getMXRecords(domain);
        } catch (NamingException e) {
            return "Unknown";
        }

        if (mxRecords.isEmpty())
            return "Invalid";

        try {
            if (isCatchAll(mxRecords, domain))
                return "Catch-All";
        } catch (Exception e) {
            return "Unknown";
        }

        Boolean smtpValid = isSmtpValid(mxRecords, email);
        if (smtpValid == null)
            return "Unknown";
        else if (smtpValid)
            return "Valid";
        else
            return "Invalid";
    }

    public boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    public String extractDomain(String email) {
        if (email == null || !email.contains("@")) return null;
        return email.substring(email.indexOf("@") + 1).toLowerCase(Locale.ROOT);
    }

    public boolean isDisposableDomain(String domain) {
        return DISPOSABLE_DOMAINS.contains(domain);
    }

    public List<String> getMXRecords(String domain) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        DirContext ctx = new InitialDirContext(env);
        Attributes attrs = ctx.getAttributes(domain, new String[]{"MX"});
        Attribute attr = attrs.get("MX");
        if (attr == null) {
            return List.of();
        }
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
        if (mxRecords.isEmpty()) return false;
        String mxHost = extractMxHost(mxRecords.get(0));
        String fakeLocal = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String fakeEmail = fakeLocal + "@" + domain;
        Boolean result = trySmtpRecipient(mxHost, fakeEmail);
        return Boolean.TRUE.equals(result);
    }

    public Boolean isSmtpValid(List<String> mxRecords, String email) {
        if (mxRecords.isEmpty()) return null;
        String mxHost = extractMxHost(mxRecords.get(0));
        return trySmtpRecipient(mxHost, email);
    }

    private Boolean trySmtpRecipient(String mxHost, String email) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(mxHost, 25), 3000);

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            String response = reader.readLine();
            if (response == null || !response.startsWith("220")) {
                return false;
            }

            writer.write("HEHLO kaalb.in\r\n");
            writer.flush();
            while ((response = reader.readLine()) != null) {
                if (response.startsWith("250 ")) break;
            }

            writer.write("MAIL FROM:<support@kaalb.in>\r\n");
            writer.flush();
            response = reader.readLine();
            if (response == null || !response.startsWith("250")) {
                return false;
            }

            // Send RCPT TO
            writer.write("RCPT TO:<" + email + ">\r\n");
            writer.flush();
            response = reader.readLine();
            if (response == null) {
                return null;
            } else if (response.startsWith("250")) {
                return true;
            } else if (response.startsWith("550")) {
                return false;
            } else {
                return null;
            }

        } catch (Exception e) {
            return null;
        }
    }

    private String extractMxHost(String mxRecord) {
        String[] parts = mxRecord.split("\\s+");
        String host = parts.length == 2 ? parts[1].trim() : mxRecord.trim();
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        return host;
    }

}