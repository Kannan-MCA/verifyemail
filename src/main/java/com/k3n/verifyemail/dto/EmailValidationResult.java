package com.k3n.verifyemail.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
public class EmailValidationResult {
    private String email;
    private String category;

    // SMTP diagnostics
    private String diagnosticTag;
    private int smtpCode;
    private String status;
    private String transcript;
    private String mailHost;
    private boolean portOpened;
    private boolean connectionSuccessful;
    private Map<String, String> errors;

    // Catch-all detection
    private boolean isCatchAll;

    // Timestamp of validation
    private String timestamp;
}