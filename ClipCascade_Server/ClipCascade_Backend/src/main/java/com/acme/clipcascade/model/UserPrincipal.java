package com.acme.clipcascade.model;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.acme.clipcascade.constants.RoleConstants;
import com.acme.clipcascade.service.BruteForceProtectionService;

public class UserPrincipal implements UserDetails {

    private Users user;

    /* transient: this is a live Spring bean, and UserDetails ends up inside the
       serialized SecurityContext whenever sessions are stored outside the heap
       (Spring Session JDBC/Redis, or Tomcat's own persistence). Serializing it
       throws NotSerializableException and every login 500s. Lockout is an
       AUTHENTICATION-time concern — by the time a session is being restored the
       credential check has already happened — so a null after deserialization
       is correct, not a hole. */
    private final transient BruteForceProtectionService bruteForceProtectionService;

    public UserPrincipal(
            Users user,
            BruteForceProtectionService bruteForceProtectionService) {

        this.user = user;
        this.bruteForceProtectionService = bruteForceProtectionService;
    }

    @Override
    public boolean isAccountNonLocked() {

        // Restored from a serialized session: the brute-force tracker is
        // transient and the credential check it guards already happened at
        // login, so there is nothing to re-validate here.
        if (bruteForceProtectionService == null) {
            return true;
        }

        // validate attempt using brute force protection
        return bruteForceProtectionService.recordAndValidateAttempt(user.getUsername());
    }

    @Override
    public boolean isEnabled() {
        return user.getEnabled();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Return a collection of roles
        return Collections.singleton(new SimpleGrantedAuthority(user.getRole()));
    }

    public boolean isAdmin() {
        return this.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority()
                        .strip()
                        .equalsIgnoreCase(RoleConstants.ADMIN));
    }

    public boolean isUser() {
        return this.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority()
                        .strip()
                        .equalsIgnoreCase(RoleConstants.USER));
    }
}
