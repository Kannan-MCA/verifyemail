package com.k3n.verifyemail.services;

import com.k3n.verifyemail.config.BlacklistDomainConfig;
import com.k3n.verifyemail.config.DisposableDomainConfig;
import com.k3n.verifyemail.config.WhitelistedDomains;
import com.k3n.verifyemail.util.SmtpRcptValidator;
import com.k3n.verifyemail.util.SmtpRcptValidator.SmtpRecipientStatus;
import com.k3n.verifyemail.util.SmtpRcptValidator.ValidationResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Service
public class MXLookupService {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$", Pattern.CASE_INSENSITIVE);

    private final Set<String> disposableDomains;
    private final Set<String> blacklistDomains;
    private final Set<String> whitelistedDomains;

    private final SmtpRcptValidator smtpRcptValidator;

    @Autowired
    public MXLookupService(DisposableDomainConfig disposableConfig,
                           BlacklistDomainConfig blacklistDomainConfig,
                           WhitelistedDomains whitelistedDomains,
                           SmtpRcptValidator smtpRcptValidator) {
        this.disposableDomains = Optional.ofNullable(disposableConfig.getDomainSet()).orElse(Collections.emptySet());
        this.blacklistDomains = Optional.ofNullable(blacklistDomainConfig.getDomainSet()).orElse(Collections.emptySet());
        this.whitelistedDomains = Optional.ofNullable(whitelistedDomains.getDomainSet()).orElse(Collections.emptySet());
        this.smtpRcptValidator = smtpRcptValidator;
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
        } catch (IOException e) {
            return "Unknown";
        }

        SmtpRecipientStatus smtpStatus = smtpCheckStatus(mxRecords, email);
        if (smtpStatus == null) return "Unknown";

        switch (smtpStatus) {
            case Valid:
                return "Valid";
            case UserNotFound:
                return "UserNotFound";
            case TemporaryFailure:
                return "Unknown";
            case UnknownFailure:
            default:
                return "Invalid";
        }
    }

    public boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    public String extractDomain(String email) {
        int atIndex = email.indexOf('@');
        return (atIndex > 0 && atIndex < email.length() - 1)
                ? email.substring(atIndex + 1).toLowerCase(Locale.ROOT)
                : null;
    }

    public boolean isDisposableDomain(String domain) {
        return disposableDomains.contains(domain);
    }

    /**
     * Retrieves MX records for the given domain.
     * @param domain The domain to look up
     * @return List of MX records as strings (format: "priority host")
     * @throws NamingException if there's an error during DNS lookup
     * @throws IllegalArgumentException if domain is null or empty
     */
    public List<String> getMXRecords(String domain) throws NamingException {
        if (domain == null || domain.trim().isEmpty()) {
            throw new IllegalArgumentException("Domain cannot be null or empty");
        }

        // Remove any trailing dot if present
        domain = domain.endsWith(".") ? domain.substring(0, domain.length() - 1) : domain;
        
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        env.put(Context.PROVIDER_URL, "dns:");
        env.put("com.sun.jndi.ldap.read.timeout", "5000"); // 5 second timeout
        
        DirContext ctx = null;
        try {
            ctx = new InitialDirContext(env);
            
            // Try to get MX records first
            Attributes attrs = ctx.getAttributes(domain, new String[]{"MX"});
            Attribute attr = attrs.get("MX");

            if (attr == null || attr.size() == 0) { // fallback to A records
                return getARecords(ctx, domain);
            }

            return processMxRecords(attr);
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (NamingException e) {
                    // Log the error but don't propagate as it's in finally
                    System.err.println("Warning: Error closing DirContext: " + e.getMessage());
                }
            }
        }
    }
    
    private List<String> getARecords(DirContext ctx, String domain) throws NamingException {
        try {
            Attributes aAttrs = ctx.getAttributes(domain, new String[]{"A"});
            Attribute aAttr = aAttrs.get("A");
            if (aAttr == null || aAttr.size() == 0) {
                return Collections.emptyList();
            }
            return IntStream.range(0, aAttr.size())
                    .mapToObj(i -> {
                        try {
                            return "0 " + aAttr.get(i).toString();
                        } catch (NamingException e) {
                            throw new RuntimeException("Failed to process A record: " + e.getMessage(), e);
                        }
                    })
                    .collect(Collectors.toList());
        } catch (NamingException e) {
            throw new NamingException("Failed to get A records for domain " + domain + ": " + e.getMessage());
        }
    }
    
    private List<String> processMxRecords(Attribute attr) throws NamingException {
        List<String> mxRecords = new ArrayList<>();
        for (int i = 0; i < attr.size(); i++) {
            try {
                String record = attr.get(i).toString();
                if (record != null && !record.trim().isEmpty()) {
                    mxRecords.add(record);
                }
            } catch (NamingException e) {
                // Log the error but continue with other records
                System.err.println("Warning: Failed to process MX record: " + e.getMessage());
            }
        }
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
        if (mxRecords == null || mxRecords.isEmpty()) return false;

        String mxHost = extractMxHost(mxRecords.get(0));
        String fakeEmail = generateRandomLocalPart() + "@" + domain;
        ValidationResult result = smtpRcptValidator.validateRecipient(mxHost, fakeEmail);
        return result != null && result.getStatus() == SmtpRecipientStatus.Valid;
    }

    private SmtpRecipientStatus smtpCheckStatus(List<String> mxRecords, String email) {
        if (mxRecords == null || mxRecords.isEmpty()) return null;

        String mxHost = extractMxHost(mxRecords.get(0));
        ValidationResult result = smtpRcptValidator.validateRecipient(mxHost, email);
        return result != null ? result.getStatus() : null;
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