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

        ValidationResult result = smtpCheckStatus(mxRecords, email);
        if (result == null) return "Unknown";

        // Optional: log diagnostics
        System.out.println("SMTP Status: " + result.getStatus());
        System.out.println("SMTP Code: " + result.getSmtpCode());
        System.out.println("Diagnostic Tag: " + result.getDiagnosticTag());
        System.out.println("Transcript:\n" + result.getFullTranscript());

        switch (result.getDiagnosticTag()) {
            case "Accepted":
                return "Valid";
            case "Forwarded":
                return "Forwarded";
            case "CannotVerify":
                return "CannotVerify";
            case "MailboxBusy":
                return "MailboxBusy";
            case "LocalError":
                return "LocalError";
            case "InsufficientStorage":
                return "InsufficientStorage";
            case "MailboxNotFound":
            case "UserNotLocal":
            case "MailboxNameInvalid":
                return "UserNotFound";
            case "RelayDenied":
                return "RelayDenied";
            case "AccessDenied":
                return "AccessDenied";
            case "Greylisted":
                return "Greylisted";
            case "SyntaxError":
                return "SyntaxError";
            case "TransactionFailed":
                return "Invalid";
            default:
                return result.getStatus() == SmtpRecipientStatus.TemporaryFailure ? "Unknown" : "Invalid";
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

    public List<String> getMXRecords(String domain) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        DirContext ctx = new InitialDirContext(env);
        Attributes attrs = ctx.getAttributes(domain, new String[]{"MX"});
        Attribute attr = attrs.get("MX");

        if (attr == null || attr.size() == 0) {
            Attributes aAttrs = ctx.getAttributes(domain, new String[]{"A"});
            Attribute aAttr = aAttrs.get("A");
            if (aAttr == null || aAttr.size() == 0) return Collections.emptyList();

            return IntStream.range(0, aAttr.size())
                    .mapToObj(i -> {
                        try {
                            return "0 " + aAttr.get(i).toString();
                        } catch (NamingException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .collect(Collectors.toList());
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
                .sorted(Comparator.comparingInt(this::parsePriority))
                .collect(Collectors.toList());

        return mxRecords;
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

    private ValidationResult smtpCheckStatus(List<String> mxRecords, String email) {
        if (mxRecords == null || mxRecords.isEmpty()) return null;

        String mxHost = extractMxHost(mxRecords.get(0));
        return smtpRcptValidator.validateRecipient(mxHost, email);
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