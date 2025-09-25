package com.k3n.verifyemail.services;

import com.k3n.verifyemail.config.BlacklistDomainConfig;
import com.k3n.verifyemail.config.DisposableDomainConfig;
import com.k3n.verifyemail.config.WhitelistedDomains;
import com.k3n.verifyemail.dto.EmailValidationResult;
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

    public EmailValidationResult categorizeEmail(String email) {
        EmailValidationResult result = new EmailValidationResult();
        result.setEmail(email);

        if (!isValidEmail(email)) {
            result.setCategory("Invalid");
            return result;
        }

        String domain = extractDomain(email);
        if (domain == null) {
            result.setCategory("Invalid");
            return result;
        }

        if (isDisposableDomain(domain)) {
            result.setCategory("Disposable");
            return result;
        }

        List<String> mxRecords;
        try {
            mxRecords = getMXRecords(domain);
        } catch (NamingException e) {
            result.setCategory("Unknown");
            return result;
        }

        if (mxRecords.isEmpty()) {
            result.setCategory("Invalid");
            return result;
        }

        try {
            if (isCatchAll(mxRecords, domain)) {
                result.setCategory("Catch-All");
                return result;
            }
        } catch (IOException e) {
            result.setCategory("Unknown");
            return result;
        }

        ValidationResult smtp = smtpCheckStatus(mxRecords, email);
        if (smtp == null) {
            result.setCategory("Unknown");
            return result;
        }

        result.setDiagnosticTag(smtp.getDiagnosticTag());
        result.setSmtpCode(smtp.getSmtpCode());
        result.setStatus(smtp.getStatus().name());
        result.setTranscript(smtp.getFullTranscript());
        result.setMailHost(smtp.getMxHost());
        result.setTimestamp(smtp.getTimestamp());
        /*
        result.setIsCatchAll(smtp.isCatchAll());
        result.setPortOpened(smtp.isPortOpened());
        result.setConnectionSuccessful(smtp.isConnectionSuccessful());
        result.setErrors(smtp.getErrorMessage());
        */


        // Categorize based on diagnostic tag
        String tag = Optional.ofNullable(smtp.getDiagnosticTag()).orElse("").trim();
        switch (tag) {
            case "Accepted": result.setCategory("Valid"); break;
            case "Forwarded": result.setCategory("Forwarded"); break;
            case "CannotVerify": result.setCategory("CannotVerify"); break;
            case "MailboxBusy": result.setCategory("MailboxBusy"); break;
            case "LocalError": result.setCategory("LocalError"); break;
            case "InsufficientStorage": result.setCategory("InsufficientStorage"); break;
            case "MailboxNotFound":
            case "UserNotLocal":
            case "MailboxNameInvalid": result.setCategory("UserNotFound"); break;
            case "RelayDenied": result.setCategory("RelayDenied"); break;
            case "AccessDenied": result.setCategory("AccessDenied"); break;
            case "Greylisted": result.setCategory("Greylisted"); break;
            case "SyntaxError": result.setCategory("SyntaxError"); break;
            case "TransactionFailed": result.setCategory("Invalid"); break;
            case "BlockedByBlacklist": result.setCategory("Blocklisted"); break;
            default:
                result.setCategory(smtp.getStatus() == SmtpRecipientStatus.TemporaryFailure ? "Unknown" : "Invalid");
        }

        return result;
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