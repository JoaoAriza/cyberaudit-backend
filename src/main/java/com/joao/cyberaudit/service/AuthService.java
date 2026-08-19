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
import org.springframework.security.core.AuthenticationException;
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
    private final AuditService        auditService;
    private final AuthThrottleService authThrottleService;

    public AuthService(AppUserRepository userRepository,
                       AccountRepository accountRepository,
                       PasswordEncoder passwordEncoder,
                       JwtUtil jwtUtil,
                       AuthenticationManager authManager,
                       PlanLimitService planLimitService,
                       TwoFactorService twoFactorService,
                       AuditService auditService,
                       AuthThrottleService authThrottleService) {
        this.userRepository    = userRepository;
        this.accountRepository = accountRepository;
        this.passwordEncoder   = passwordEncoder;
        this.jwtUtil           = jwtUtil;
        this.authManager       = authManager;
        this.planLimitService  = planLimitService;
        this.twoFactorService  = twoFactorService;
        this.auditService      = auditService;
        this.authThrottleService = authThrottleService;
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
        PasswordPolicy.validate(req.getPassword());
        PasswordPolicy.validateIdentity(req.getName(), req.getEmail());

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

    public AuthResponse login(LoginRequest req, String clientIp) {
        String email = req.getEmail().toLowerCase().trim();

        // Antes da senha: conta ou IP já travados por tentativas anteriores.
        authThrottleService.checkLoginAllowed(email, clientIp);

        try {
            authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, req.getPassword())
            );
        } catch (AuthenticationException e) {
            authThrottleService.recordLoginFailure(email, clientIp);
            auditService.log(null, null, email, null,
                    AuditAction.LOGIN_FAILED, null, false);
            throw e;
        }
        authThrottleService.recordLoginSuccess(email, clientIp);

        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Credenciais inválidas."));

        if (!user.isActive()) {
            auditService.log(null, user.getId(), user.getEmail(), user.getName(),
                    AuditAction.LOGIN_FAILED, "Conta desativada", false);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Conta desativada. Entre em contato com o administrador.");
        }

        // 2FA habilitado → retorna pre-auth token (login real registrado em verify2fa)
        if (twoFactorService.isEnabled(user)) {
            if (user.isEmailOtpEnabled()) {
                try {
                    twoFactorService.sendEmailOtp(user);
                } catch (com.joao.cyberaudit.exception.EmailDeliveryException e) {
                    // Com TOTP também ativo, o e-mail é só uma das opções: seguir em
                    // frente deixa o usuário entrar pelo app autenticador. Se o e-mail
                    // era o único fator, a falha tem de aparecer — devolver a tela de
                    // código escondendo isso é o que trancava a conta.
                    if (!user.isTotpEnabled()) throw e;
                    System.err.println("[Auth] OTP por e-mail falhou, seguindo com TOTP: "
                            + e.getMessage());
                }
            }
            String preAuthToken = jwtUtil.generatePreAuthToken(user);
            return new AuthResponse(preAuthToken, twoFactorService.getMethods(user));
        }

        auditService.log(user, AuditAction.LOGIN_SUCCESS, null);
        String token = jwtUtil.generateToken(user);
        return new AuthResponse(token, UserDto.from(user, planLimitService));
    }

    // ── Auto-registro ─────────────────────────────────────────────────────────

    /**
     * Cria uma nova conta (plan FREE) e seu usuário OWNER via auto-registro público.
     * Retorna JWT → auto-login imediato.
     */
    @Transactional
    public AuthResponse register(RegisterRequest req) {
        // Validações básicas
        if (!req.isTermsAccepted()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "É necessário aceitar os Termos de Uso e Política de Privacidade.");
        }
        if (req.getName() == null || req.getName().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nome é obrigatório.");
        }
        if (req.getEmail() == null || req.getEmail().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email é obrigatório.");
        }
        PasswordPolicy.validate(req.getPassword());
        PasswordPolicy.validateIdentity(req.getName(), req.getEmail());

        String email = req.getEmail().toLowerCase().trim();

        if (userRepository.findByEmail(email).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Email já cadastrado. Faça login ou use outro endereço.");
        }

        // Cria conta e usuário
        Account account = buildAccountFromRegister(req);
        accountRepository.save(account);

        AppUser user = AppUser.builder()
                .name(req.getName().trim())
                .email(email)
                .passwordHash(passwordEncoder.encode(req.getPassword()))
                .role(Role.OWNER)
                .active(true)
                .createdAt(LocalDateTime.now())
                .account(account)
                .termsAccepted(true)
                .termsAcceptedAt(LocalDateTime.now())
                .build();

        userRepository.save(user);
        auditService.log(user, AuditAction.LOGIN_SUCCESS, "auto-register");

        String token = jwtUtil.generateToken(user);
        return new AuthResponse(token, UserDto.from(user, planLimitService));
    }

    private Account buildAccountFromRegister(RegisterRequest req) {
        Account.AccountBuilder builder = Account.builder()
                .type(req.getAccountType() != null ? req.getAccountType() : AccountType.INDIVIDUAL)
                .plan(Plan.FREE)
                .country(req.getCountry())
                .createdAt(LocalDateTime.now());

        if (req.getAccountType() == AccountType.COMPANY) {
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
                    .displayName(req.getName().trim())
                    .fullName(req.getName().trim())
                    .profession(req.getProfession())
                    .website(req.getWebsite());
        }

        return builder.build();
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