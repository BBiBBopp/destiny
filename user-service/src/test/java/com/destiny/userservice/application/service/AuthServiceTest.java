package com.destiny.userservice.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.destiny.global.code.CommonErrorCode;
import com.destiny.global.exception.BizException;
import com.destiny.userservice.application.cache.AuthCache;
import com.destiny.userservice.domain.entity.User;
import com.destiny.userservice.domain.entity.UserRole;
import com.destiny.userservice.domain.repository.UserRepository;
import com.destiny.userservice.infrastructure.security.auth.CustomUserDetails;
import com.destiny.userservice.infrastructure.security.jwt.JwtUtil;
import com.destiny.userservice.presentation.advice.UserErrorCode;
import com.destiny.userservice.presentation.aop.TokenContextHolder;
import com.destiny.userservice.presentation.dto.request.MasterSignUpRequest;
import com.destiny.userservice.presentation.dto.request.UserLoginRequest;
import com.destiny.userservice.presentation.dto.request.UserSignUpRequest;
import com.destiny.userservice.presentation.dto.response.UserLoginResponse;
import com.destiny.userservice.presentation.dto.response.UserSignUpResponse;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private AuthCache authCache;

    @InjectMocks
    private AuthService authService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "masterAdminToken", "test-admin-token");
    }

    @AfterEach
    void tearDown() {
        TokenContextHolder.clear();
    }

    // ── userSignUp ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("일반 회원가입 성공 - CUSTOMER 역할로 저장된다")
    void userSignUp_성공_CUSTOMER() {
        // given
        UserSignUpRequest request = createUserSignUpRequest("testuser", UserRole.CUSTOMER);

        when(userRepository.existsByUsernameAndDeletedAtIsNull("testuser")).thenReturn(false);
        when(passwordEncoder.encode(request.password())).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        // when
        UserSignUpResponse response = authService.userSignUp(request);

        // then
        assertNotNull(response);
        assertEquals("testuser", response.username());
        assertEquals(UserRole.CUSTOMER, response.userRole());
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("일반 회원가입 성공 - userRole이 null이면 기본값 CUSTOMER로 저장된다")
    void userSignUp_성공_역할_null이면_CUSTOMER() {
        // given
        UserSignUpRequest request = createUserSignUpRequest("testuser", null);

        when(userRepository.existsByUsernameAndDeletedAtIsNull("testuser")).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("encoded");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        // when
        UserSignUpResponse response = authService.userSignUp(request);

        // then
        assertEquals(UserRole.CUSTOMER, response.userRole());
    }

    @Test
    @DisplayName("일반 회원가입 실패 - 이미 존재하는 username이면 예외가 발생한다")
    void userSignUp_실패_username_중복() {
        // given
        UserSignUpRequest request = createUserSignUpRequest("testuser", null);

        when(userRepository.existsByUsernameAndDeletedAtIsNull("testuser")).thenReturn(true);

        // when
        BizException ex = assertThrows(BizException.class, () -> authService.userSignUp(request));

        // then
        assertEquals(UserErrorCode.USER_ALREADY_EXISTS, ex.getResponseCode());
        verify(userRepository, never()).save(any());
    }

    // ── masterSignUp ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("마스터 회원가입 성공 - PARTNER 역할은 admin token 없이도 가입 가능하다")
    void masterSignUp_성공_PARTNER() {
        // given
        MasterSignUpRequest request = new MasterSignUpRequest(
            "partner1", "Partner1234!", "partner@email.com",
            UserRole.PARTNER, null
        );

        when(userRepository.existsByUsernameAndDeletedAtIsNull("partner1")).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("encoded");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        // when
        UserSignUpResponse response = authService.masterSignUp(request);

        // then
        assertNotNull(response);
        assertEquals("partner1", response.username());
    }

    @Test
    @DisplayName("마스터 회원가입 성공 - MASTER 역할 + 올바른 admin token으로 가입 가능하다")
    void masterSignUp_성공_MASTER_올바른_토큰() {
        // given
        MasterSignUpRequest request = new MasterSignUpRequest(
            "admin1", "Admin1234!", "admin@email.com",
            UserRole.MASTER, "test-admin-token"
        );

        when(userRepository.existsByUsernameAndDeletedAtIsNull("admin1")).thenReturn(false);
        when(passwordEncoder.encode(any())).thenReturn("encoded");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        // when
        UserSignUpResponse response = authService.masterSignUp(request);

        // then
        assertNotNull(response);
        assertEquals("admin1", response.username());
    }

    @Test
    @DisplayName("마스터 회원가입 실패 - 이미 존재하는 username이면 예외가 발생한다")
    void masterSignUp_실패_username_중복() {
        // given
        MasterSignUpRequest request = new MasterSignUpRequest(
            "admin1", "Admin1234!", "admin@email.com",
            UserRole.MASTER, "test-admin-token"
        );

        when(userRepository.existsByUsernameAndDeletedAtIsNull("admin1")).thenReturn(true);

        // when
        BizException ex = assertThrows(BizException.class, () -> authService.masterSignUp(request));

        // then
        assertEquals(UserErrorCode.USER_ALREADY_EXISTS, ex.getResponseCode());
        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("마스터 회원가입 실패 - MASTER 역할에 잘못된 admin token을 제출하면 예외가 발생한다")
    void masterSignUp_실패_MASTER_잘못된_토큰() {
        // given
        MasterSignUpRequest request = new MasterSignUpRequest(
            "admin1", "Admin1234!", "admin@email.com",
            UserRole.MASTER, "wrong-token"
        );

        when(userRepository.existsByUsernameAndDeletedAtIsNull("admin1")).thenReturn(false);

        // when
        BizException ex = assertThrows(BizException.class, () -> authService.masterSignUp(request));

        // then
        assertEquals(UserErrorCode.INVALID_ADMIN_TOKEN, ex.getResponseCode());
        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("마스터 회원가입 실패 - MASTER 역할에 null admin token을 제출하면 예외가 발생한다")
    void masterSignUp_실패_MASTER_null_토큰() {
        // given
        MasterSignUpRequest request = new MasterSignUpRequest(
            "admin1", "Admin1234!", "admin@email.com",
            UserRole.MASTER, null
        );

        when(userRepository.existsByUsernameAndDeletedAtIsNull("admin1")).thenReturn(false);

        // when
        BizException ex = assertThrows(BizException.class, () -> authService.masterSignUp(request));

        // then
        assertEquals(UserErrorCode.INVALID_ADMIN_TOKEN, ex.getResponseCode());
        verify(userRepository, never()).save(any());
    }

    // ── login ────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("로그인 성공 - 올바른 자격증명으로 응답이 반환되고 TokenContextHolder에 토큰이 저장된다")
    void login_성공() {
        // given
        UUID userId = UUID.randomUUID();
        UserLoginRequest request = new UserLoginRequest("testuser", "Test1234!");
        User mockUser = mock(User.class);

        when(userRepository.findByUsernameAndDeletedAtIsNull("testuser")).thenReturn(mockUser);
        when(mockUser.getPassword()).thenReturn("encoded");
        when(passwordEncoder.matches("Test1234!", "encoded")).thenReturn(true);
        when(mockUser.getUserId()).thenReturn(userId);
        when(jwtUtil.generateAccessToken(mockUser)).thenReturn("access-token");
        when(jwtUtil.generateRefreshToken(userId.toString())).thenReturn("refresh-token");

        // when
        UserLoginResponse response = authService.login(request);

        // then
        assertNotNull(response);
        assertThat(TokenContextHolder.getTokens().accessToken()).isEqualTo("access-token");
        assertThat(TokenContextHolder.getTokens().refreshToken()).isEqualTo("refresh-token");
    }

    @Test
    @DisplayName("로그인 실패 - 비밀번호가 일치하지 않으면 예외가 발생한다")
    void login_실패_비밀번호_불일치() {
        // given
        UserLoginRequest request = new UserLoginRequest("testuser", "WrongPass!");
        User mockUser = mock(User.class);

        when(userRepository.findByUsernameAndDeletedAtIsNull("testuser")).thenReturn(mockUser);
        when(mockUser.getPassword()).thenReturn("encoded");
        when(passwordEncoder.matches("WrongPass!", "encoded")).thenReturn(false);

        // when
        BizException ex = assertThrows(BizException.class, () -> authService.login(request));

        // then
        assertEquals(UserErrorCode.INVALID_LOGIN_CREDENTIALS, ex.getResponseCode());
    }

    // ── logout ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("로그아웃 성공 - 자기 자신을 로그아웃하면 logout()이 호출되고 캐시에 저장된다")
    void logout_성공_자기자신() {
        // given
        UUID userId = UUID.randomUUID();
        CustomUserDetails userDetails = mock(CustomUserDetails.class);
        when(userDetails.getUserId()).thenReturn(userId);
        when(userDetails.getUserRole()).thenReturn("CUSTOMER");

        User mockUser = mock(User.class);
        when(userRepository.findById(userId)).thenReturn(mockUser);

        // when
        authService.logout(userDetails, null);

        // then
        verify(mockUser).logout();
        verify(authCache).storeToken(anyString(), anyLong());
    }

    @Test
    @DisplayName("로그아웃 성공 - MASTER는 다른 사용자를 강제 로그아웃시킬 수 있다")
    void logout_성공_MASTER가_타사용자_강제_로그아웃() {
        // given
        UUID masterUserId = UUID.randomUUID();
        UUID targetUserId = UUID.randomUUID();
        CustomUserDetails masterDetails = mock(CustomUserDetails.class);
        when(masterDetails.getUserId()).thenReturn(masterUserId);
        when(masterDetails.getUserRole()).thenReturn("MASTER");

        User targetUser = mock(User.class);
        when(userRepository.findById(targetUserId)).thenReturn(targetUser);

        // when
        authService.logout(masterDetails, targetUserId);

        // then
        verify(targetUser).logout();
        verify(authCache).storeToken(anyString(), anyLong());
    }

    @Test
    @DisplayName("로그아웃 실패 - CUSTOMER가 다른 사용자를 로그아웃 시도하면 ACCESS_DENIED가 발생한다")
    void logout_실패_CUSTOMER_타사용자_로그아웃_시도() {
        // given
        UUID authUserId = UUID.randomUUID();
        UUID targetUserId = UUID.randomUUID();
        CustomUserDetails userDetails = mock(CustomUserDetails.class);
        when(userDetails.getUserId()).thenReturn(authUserId);
        when(userDetails.getUserRole()).thenReturn("CUSTOMER");

        // when
        BizException ex = assertThrows(BizException.class,
            () -> authService.logout(userDetails, targetUserId));

        // then
        assertEquals(CommonErrorCode.ACCESS_DENIED, ex.getResponseCode());
        verify(authCache, never()).storeToken(any(), any());
    }

    // ── reissueAccessToken ───────────────────────────────────────────────────

    @Test
    @DisplayName("토큰 재발급 실패 - null 리프레시 토큰이면 예외가 발생한다")
    void reissueAccessToken_실패_null_토큰() {
        BizException ex = assertThrows(BizException.class,
            () -> authService.reissueAccessToken(null));

        assertEquals(UserErrorCode.REFRESH_TOKEN_MISSING, ex.getResponseCode());
    }

    @Test
    @DisplayName("토큰 재발급 실패 - 빈 리프레시 토큰이면 예외가 발생한다")
    void reissueAccessToken_실패_빈_토큰() {
        BizException ex = assertThrows(BizException.class,
            () -> authService.reissueAccessToken("   "));

        assertEquals(UserErrorCode.REFRESH_TOKEN_MISSING, ex.getResponseCode());
    }

    @Test
    @DisplayName("토큰 재발급 성공 - 로그아웃 이력 없고 만료 여유가 충분하면 access token만 발급된다")
    void reissueAccessToken_성공_로그아웃없음_rotation_불필요() {
        // given
        UUID userId = UUID.randomUUID();
        DecodedJWT decodedJwt = mock(DecodedJWT.class);
        Claim claim = mock(Claim.class);
        User user = mock(User.class);

        when(jwtUtil.verifyRefreshToken("refresh-token")).thenReturn(decodedJwt);
        when(decodedJwt.getClaim("userId")).thenReturn(claim);
        when(claim.asString()).thenReturn(userId.toString());
        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(user);
        when(user.getLogoutTime()).thenReturn(null);
        // 만료까지 10일 남음 → rotation 불필요
        when(decodedJwt.getExpiresAtAsInstant()).thenReturn(Instant.now().plusSeconds(10L * 24 * 3600));
        when(jwtUtil.generateAccessToken(user)).thenReturn("new-access-token");

        // when
        authService.reissueAccessToken("refresh-token");

        // then
        assertThat(TokenContextHolder.getTokens().accessToken()).isEqualTo("new-access-token");
        assertThat(TokenContextHolder.getTokens().refreshToken()).isNull();
        verify(jwtUtil, never()).generateRefreshToken(any());
    }

    @Test
    @DisplayName("토큰 재발급 성공 - 만료가 3일 이하로 남으면 refresh token도 함께 재발급된다")
    void reissueAccessToken_성공_rotation_발생() {
        // given
        UUID userId = UUID.randomUUID();
        DecodedJWT decodedJwt = mock(DecodedJWT.class);
        Claim claim = mock(Claim.class);
        User user = mock(User.class);

        when(jwtUtil.verifyRefreshToken("refresh-token")).thenReturn(decodedJwt);
        when(decodedJwt.getClaim("userId")).thenReturn(claim);
        when(claim.asString()).thenReturn(userId.toString());
        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(user);
        when(user.getLogoutTime()).thenReturn(null);
        when(user.getUserId()).thenReturn(userId);
        // 만료까지 2일 남음 → rotation 필요
        when(decodedJwt.getExpiresAtAsInstant()).thenReturn(Instant.now().plusSeconds(2L * 24 * 3600));
        when(jwtUtil.generateAccessToken(user)).thenReturn("new-access-token");
        when(jwtUtil.generateRefreshToken(userId.toString())).thenReturn("new-refresh-token");

        // when
        authService.reissueAccessToken("refresh-token");

        // then
        assertThat(TokenContextHolder.getTokens().accessToken()).isEqualTo("new-access-token");
        assertThat(TokenContextHolder.getTokens().refreshToken()).isEqualTo("new-refresh-token");
    }

    @Test
    @DisplayName("토큰 재발급 실패 - 로그아웃 이전에 발급된 토큰으로 재발급 요청 시 ACCESS_DENIED가 발생한다")
    void reissueAccessToken_실패_로그아웃_이전_발급_토큰() {
        // given
        UUID userId = UUID.randomUUID();
        DecodedJWT decodedJwt = mock(DecodedJWT.class);
        Claim claim = mock(Claim.class);
        User user = mock(User.class);

        when(jwtUtil.verifyRefreshToken("stale-token")).thenReturn(decodedJwt);
        when(decodedJwt.getClaim("userId")).thenReturn(claim);
        when(claim.asString()).thenReturn(userId.toString());
        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(user);
        // 로그아웃 시각 = 지금
        when(user.getLogoutTime()).thenReturn(LocalDateTime.now());
        // 토큰 발급 시각 = 로그아웃보다 1시간 전 → 유효하지 않음
        when(decodedJwt.getIssuedAt()).thenReturn(Date.from(Instant.now().minusSeconds(3600)));

        // when
        BizException ex = assertThrows(BizException.class,
            () -> authService.reissueAccessToken("stale-token"));

        // then
        assertEquals(CommonErrorCode.ACCESS_DENIED, ex.getResponseCode());
    }

    @Test
    @DisplayName("토큰 재발급 성공 - 로그아웃 이후에 발급된 토큰은 유효하다")
    void reissueAccessToken_성공_로그아웃_이후_발급_토큰() {
        // given
        UUID userId = UUID.randomUUID();
        DecodedJWT decodedJwt = mock(DecodedJWT.class);
        Claim claim = mock(Claim.class);
        User user = mock(User.class);

        when(jwtUtil.verifyRefreshToken("fresh-token")).thenReturn(decodedJwt);
        when(decodedJwt.getClaim("userId")).thenReturn(claim);
        when(claim.asString()).thenReturn(userId.toString());
        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(user);
        // 로그아웃 시각 = 1시간 전, 토큰 발급 시각 = 30분 전 → 유효
        when(user.getLogoutTime()).thenReturn(LocalDateTime.now().minusHours(1));
        when(decodedJwt.getIssuedAt()).thenReturn(Date.from(Instant.now().minusSeconds(1800)));
        // 만료까지 10일 남음 → rotation 불필요
        when(decodedJwt.getExpiresAtAsInstant()).thenReturn(Instant.now().plusSeconds(10L * 24 * 3600));
        when(jwtUtil.generateAccessToken(user)).thenReturn("new-access-token");

        // when
        authService.reissueAccessToken("fresh-token");

        // then
        assertThat(TokenContextHolder.getTokens().accessToken()).isEqualTo("new-access-token");
    }

    // ── toDate ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("toDate - null 입력 시 null을 반환한다")
    void toDate_null_입력_시_null_반환() {
        assertNull(authService.toDate(null));
    }

    @Test
    @DisplayName("toDate - LocalDateTime 입력 시 해당 시각의 Date를 반환한다")
    void toDate_LocalDateTime_입력_시_Date_반환() {
        // given
        LocalDateTime ldt = LocalDateTime.of(2025, 6, 15, 12, 0, 0);

        // when
        Date result = authService.toDate(ldt);

        // then
        assertNotNull(result);
        assertThat(result.toInstant().atZone(java.time.ZoneId.of("Asia/Seoul")).toLocalDateTime())
            .isEqualTo(ldt);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private UserSignUpRequest createUserSignUpRequest(String username, UserRole userRole) {
        return new UserSignUpRequest(
            username,
            "Test1234!",
            "test@email.com",
            userRole,
            "닉네임",
            "010-1234-5678",
            "12345",
            "서울시 강남구 테헤란로 1길",
            "101동 101호",
            LocalDate.of(2000, 1, 1)
        );
    }
}
