package com.k3n.verifyemail.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k3n.verifyemail.dto.EmailValidationResult;
import com.k3n.verifyemail.model.EmailEntity;
import com.k3n.verifyemail.model.EmailVerificationResultEntity;
import com.k3n.verifyemail.repository.emailrepository;
import com.k3n.verifyemail.repository.emailverificationresultrepository;
import com.k3n.verifyemail.services.MXLookupService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/email")
public class EmailValidationController {

    @Autowired
    private MXLookupService mxLookupService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private emailrepository emailRepository;

    @Autowired
    private emailverificationresultrepository resultRepository;

    @GetMapping
    public ResponseEntity<?> verifySingleEmail(@RequestParam String email) {
        EmailValidationResult result = mxLookupService.categorizeEmail(email);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/batch")
    public ResponseEntity<?> verifyBatchEmails(@RequestBody List<String> emails) {
        Map<String, EmailValidationResult> resultMap = new HashMap<>();
        for (String email : emails) {
            EmailValidationResult result = mxLookupService.categorizeEmail(email);
            resultMap.put(email, result);
        }
        return ResponseEntity.ok(resultMap);
    }

    @PostMapping("/process-from-db")
    public ResponseEntity<?> processEmailsFromDb() {
        List<EmailEntity> emails = emailRepository.findAll();

        for (EmailEntity emailEntity : emails) {
            String email = emailEntity.getEmail();
            EmailValidationResult result = mxLookupService.categorizeEmail(email);

            try {
                String jsonResult = objectMapper.writeValueAsString(result);
                EmailVerificationResultEntity resultEntity = new EmailVerificationResultEntity();
                resultEntity.setEmail(email);
                resultEntity.setVerificationResultJson(jsonResult);
                resultRepository.save(resultEntity);
            } catch (JsonProcessingException e) {
                System.out.println(e.getMessage());
            }
        }

        return ResponseEntity.ok(Map.of("message", "Processed and stored email validation results."));
    }
}