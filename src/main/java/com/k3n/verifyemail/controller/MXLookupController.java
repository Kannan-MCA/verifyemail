package com.k3n.verifyemail.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k3n.verifyemail.model.EmailEntity;
import com.k3n.verifyemail.model.EmailVerificationResultEntity;
import com.k3n.verifyemail.repository.emailrepository;
import com.k3n.verifyemail.repository.emailverificationresultrepository;
import com.k3n.verifyemail.services.MXLookupService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.naming.NamingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/mxlookup")
public class MXLookupController
{
    private final MXLookupService mxLookupService;
    private final emailrepository emailRepository;
    private final emailverificationresultrepository resultRepository;
    private final ObjectMapper objectMapper;

    public MXLookupController(MXLookupService mxLookupService,
                              emailrepository emailRepository,
                              emailverificationresultrepository resultRepository,
                              ObjectMapper objectMapper) {
        this.mxLookupService = mxLookupService;
        this.emailRepository = emailRepository;
        this.resultRepository = resultRepository;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/email")
    public ResponseEntity<?> verifySingleEmail(@RequestParam String email) {
        String category = mxLookupService.categorizeEmail(email);
        Map<String, Object> resp = new HashMap<>();
        resp.put("email", email);
        resp.put("category", category);
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/emails")
    public ResponseEntity<?> verifyBatchEmails(@RequestBody List<String> emails) {
        Map<String, Object> result = new HashMap<>();
        for (String email : emails) {
            result.put(email, mxLookupService.categorizeEmail(email));
        }
        return ResponseEntity.ok(result);
    }

    @PostMapping("/process-from-db")
    public ResponseEntity<?> processEmailsFromDb() {
        List<EmailEntity> emails = emailRepository.findAll();
        for (EmailEntity emailEntity : emails) {
            String email = emailEntity.getEmail();
            String category = mxLookupService.categorizeEmail(email);
            Map<String, Object> resultDetails = new HashMap<>();
            resultDetails.put("email", email);
            resultDetails.put("category", category);
            try {
                String jsonResult = objectMapper.writeValueAsString(resultDetails);
                EmailVerificationResultEntity resultEntity = new EmailVerificationResultEntity();
                resultEntity.setEmail(email);
                resultEntity.setVerificationResultJson(jsonResult);
                resultRepository.save(resultEntity);
            } catch (JsonProcessingException e) {
                // Handle exception as needed
            }
        }
        return ResponseEntity.ok(Map.of("message", "Processed and stored email validation results."));
    }

}