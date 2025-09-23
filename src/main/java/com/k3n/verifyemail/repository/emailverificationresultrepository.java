package com.k3n.verifyemail.repository;

import com.k3n.verifyemail.model.EmailVerificationResultEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface emailverificationresultrepository extends JpaRepository<EmailVerificationResultEntity, Long> {
}
