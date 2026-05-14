package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.*;
import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.security.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;

@Service
public class AuthService {

    private final AppUserRepository   userRepository;
    private final AccountRepository   accountRepository;
    private final PasswordEncoder     passwordEncoder;
    private final JwtUtil             jwtUtil;
    private final AuthenticationManager authManager;

    public AuthService(AppUserRepository userRepository,
                       AccountRepository accountRepository,
                       PasswordEncoder passwordEncoder,
                       JwtUtil jwtUtil,
                       AuthenticationManager authManager) {
        this.userRepository  = userRepository;
        this.accountRepository = accountRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil         = jwtUtil;
        this.authManager     = authManager;
    }

    @Transactional
    public AuthResponse setup(SetupRequest req) {
        if (userRepository.count() > 0) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Sistema já configurado. Use /auth/login.");
        }

        Account account = buildAccount(req);
        accountRepository.save(account);

        AppUser owner = AppUser.builder()
                .name(req.getName())
                .email(req.getEmail().toLowerCase().trim())
                .passwordHash(passwordEncoder.encode(req.getPassword()))
                .role(Role.OWNER)
                .active(true)
                .createdAt(LocalDateTime.now())
                .account(account)
                .build();

        userRepository.save(owner);

        String token = jwtUtil.generateToken(owner);
        return new AuthResponse(token, UserDto.from(owner));
    }

    public AuthResponse login(LoginRequest req) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        req.getEmail().toLowerCase().trim(),
                        req.getPassword()
                )
        );

        AppUser user = userRepository.findByEmail(req.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Credenciais inválidas."));

        if (!user.isActive()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Conta desativada. Entre em contato com o administrador.");
        }

        String token = jwtUtil.generateToken(user);
        return new AuthResponse(token, UserDto.from(user));
    }

    private Account buildAccount(SetupRequest req) {
        Account.AccountBuilder builder = Account.builder()
                .type(req.getAccountType())
                .country(req.getCountry())
                .createdAt(LocalDateTime.now());

        if (req.getAccountType() == AccountType.COMPANY) {
            builder
                    .displayName(req.getCompanyName() != null
                            ? req.getCompanyName() : req.getName())
                    .companyName(req.getCompanyName())
                    .companyDomain(req.getCompanyDomain())
                    .companySize(req.getCompanySize());
        } else {
            builder
                    .displayName(req.getName())
                    .fullName(req.getName())
                    .profession(req.getProfession())
                    .website(req.getWebsite());
        }

        return builder.build();
    }
}