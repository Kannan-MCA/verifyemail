package com.k3n.verifyemail.repository;

import com.k3n.verifyemail.model.EmailEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface emailrepository extends JpaRepository<EmailEntity, Long> {
}