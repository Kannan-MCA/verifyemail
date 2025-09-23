package com.k3n.verifyemail.model;

import jakarta.persistence.*;

@Entity
@Table(name = "email_verification_results")
public class EmailVerificationResultEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;

    @Lob
    private String verificationResultJson;  // Storing JSON result as string

    // getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getVerificationResultJson() { return verificationResultJson; }
    public void setVerificationResultJson(String verificationResultJson) { this.verificationResultJson = verificationResultJson; }
}