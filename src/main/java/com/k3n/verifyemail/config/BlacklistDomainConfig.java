package com.k3n.verifyemail.config;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
@ConfigurationProperties(prefix = "blacklisted")
public class BlacklistDomainConfig {

    private List<String> domains;

    public List<String> getDomains() {
        return domains;
    }

    public void setDomains(List<String> domains) {
        this.domains = domains;
    }

    public Set<String> getDomainSet() {
        return new HashSet<>(domains);
    }

    @PostConstruct
    public void logDomains() {
        System.out.println("Blaklisted domains loaded: " + domains);
    }
}
