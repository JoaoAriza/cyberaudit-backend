package com.joao.cyberaudit.service;

import com.joao.cyberaudit.dto.*;
import com.joao.cyberaudit.model.*;
import com.joao.cyberaudit.repository.AccountRepository;
import com.joao.cyberaudit.repository.AppUserRepository;
import com.joao.cyberaudit.security.JwtUtil;
import com.joao.cyberaudit.util.CnpjUtil;
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
    private final PlanLimitService    planLimitService;
    private final TwoFactorService    twoFactorService;

    public AuthService(AppUserRepository userRepository,
                       AccountRepository accountRepository,
                       PasswordEncoder passwordEncoder,
                       JwtUtil jwtUtil,
                       AuthenticationManager authManager,
                       PlanLimitService planLimitService,
                       TwoFactorService twoFactorService) {
        this.userRepository    = userRepository;
        this.accountRepository = accountRepository;
        this.passwordEncoder   = passwordEncoder;
        this.jwtUtil           = jwtUtil;
        this.authManager       = authManager;
        this.planLimitService  = planLimitService;
        this.twoFactorService  = twoFactorService;
    }

    @Transactional
    public AuthResponse setup(SetupRequest req) {
        if (userRepository.count() > 0) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Sistema já configurado. Use /auth/login.");
        }

        if (!req.isTermsAccepted()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "É necessário aceitar os Termos de Uso e Política de Privacidade.");
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
                .termsAccepted(true)
                .termsAcceptedAt(LocalDateTime.now())
                .build();

        userRepository.save(owner);

        String token = jwtUtil.generateToken(owner);
        return new AuthResponse(token, UserDto.from(owner, planLimitService));
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

        // 2FA habilitado → retorna pre-auth token
        if (twoFactorService.isEnabled(user)) {
            if (user.isEmailOtpEnabled()) {
                twoFactorService.sendEmailOtp(user); // envia código imediatamente
            }
            String preAuthToken = jwtUtil.generatePreAuthToken(user);
            return new AuthResponse(preAuthToken, twoFactorService.getMethods(user));
        }

        String token = jwtUtil.generateToken(user);
        return new AuthResponse(token, UserDto.from(user, planLimitService));
    }

    private Account buildAccount(SetupRequest req) {
        Account.AccountBuilder builder = Account.builder()
                .type(req.getAccountType())
                .country(req.getCountry())
                .createdAt(LocalDateTime.now());

        if (req.getAccountType() == AccountType.COMPANY) {
            // Valida CNPJ obrigatório para conta COMPANY
            String rawCnpj = req.getCnpj();
            if (rawCnpj == null || rawCnpj.isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "CNPJ é obrigatório para contas empresa.");
            }
            if (!CnpjUtil.isValid(rawCnpj)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "CNPJ inválido: " + rawCnpj);
            }
            builder
                    .displayName(req.getCompanyName() != null
                            ? req.getCompanyName() : req.getName())
                    .companyName(req.getCompanyName())
                    .companyDomain(req.getCompanyDomain())
                    .companySize(req.getCompanySize())
                    .cnpj(CnpjUtil.strip(rawCnpj));
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