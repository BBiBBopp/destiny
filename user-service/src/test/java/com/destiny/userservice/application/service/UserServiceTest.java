package com.destiny.userservice.application.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.destiny.global.code.CommonErrorCode;
import com.destiny.global.exception.BizException;
import com.destiny.userservice.application.cache.AuthCache;
import com.destiny.userservice.domain.entity.User;
import com.destiny.userservice.domain.entity.UserInfo;
import com.destiny.userservice.domain.entity.UserRole;
import com.destiny.userservice.domain.repository.UserRepository;
import com.destiny.userservice.presentation.advice.UserErrorCode;
import com.destiny.userservice.presentation.dto.request.UserPasswordUpdateRequest;
import com.destiny.userservice.presentation.dto.request.UserUpdateRequest;
import com.destiny.userservice.presentation.dto.response.UserGetResponse;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthCache authCache;

    @InjectMocks
    private UserService userService;

    // ── getUser ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("단건 조회 성공 - 자기 자신의 정보를 조회할 수 있다")
    void getUser_성공_자기자신() {
        // given
        UUID userId = UUID.randomUUID();
        User mockUser = buildMockUser(userId, UserRole.CUSTOMER);

        when(userRepository.findById(userId)).thenReturn(mockUser);

        // when
        UserGetResponse response = userService.getUser(userId, UserRole.CUSTOMER, userId);

        // then
        assertNotNull(response);
        assertEquals(userId, response.userId());
        verify(userRepository).findById(userId);
    }

    @Test
    @DisplayName("단건 조회 성공 - MASTER는 다른 사용자 정보를 조회할 수 있다")
    void getUser_성공_MASTER_타사용자_조회() {
        // given
        UUID masterId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        User mockUser = buildMockUser(targetId, UserRole.CUSTOMER);

        when(userRepository.findById(targetId)).thenReturn(mockUser);

        // when
        UserGetResponse response = userService.getUser(masterId, UserRole.MASTER, targetId);

        // then
        assertNotNull(response);
        verify(userRepository).findById(targetId);
    }

    @Test
    @DisplayName("단건 조회 실패 - CUSTOMER가 다른 사용자 조회 시도 시 ACCESS_DENIED가 발생한다")
    void getUser_실패_CUSTOMER_타사용자_조회() {
        // given
        UUID authId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();

        // when
        BizException ex = assertThrows(BizException.class,
            () -> userService.getUser(authId, UserRole.CUSTOMER, targetId));

        // then
        assertEquals(CommonErrorCode.ACCESS_DENIED, ex.getResponseCode());
        verify(userRepository, never()).findById(any());
    }

    // ── updateUser ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("사용자 수정 성공 - 이메일과 프로필 정보가 모두 업데이트된다")
    void updateUser_성공_이메일_프로필_수정() {
        // given
        UUID userId = UUID.randomUUID();
        User mockUser = mock(User.class);
        UserInfo mockUserInfo = mock(UserInfo.class);
        UserUpdateRequest request = new UserUpdateRequest("새닉네임", "010-9999-8888", "new@email.com", "99999", "새주소1", "새주소2");

        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(mockUser);
        when(mockUser.getUserInfo()).thenReturn(mockUserInfo);
        when(mockUser.getUserId()).thenReturn(userId);
        when(mockUser.getUserRole()).thenReturn(UserRole.CUSTOMER);

        // when
        userService.updateUser(userId, UserRole.CUSTOMER, userId, request);

        // then
        verify(mockUser).changeEmail("new@email.com");
        verify(mockUserInfo).updateProfile(request);
    }

    @Test
    @DisplayName("사용자 수정 성공 - email이 null이면 이메일은 변경되지 않는다")
    void updateUser_성공_email_null_이면_이메일_변경없음() {
        // given
        UUID userId = UUID.randomUUID();
        User mockUser = mock(User.class);
        UserUpdateRequest request = new UserUpdateRequest("새닉네임", null, null, null, null, null);

        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(mockUser);
        when(mockUser.getUserInfo()).thenReturn(null);
        when(mockUser.getUserId()).thenReturn(userId);
        when(mockUser.getUserRole()).thenReturn(UserRole.CUSTOMER);

        // when
        userService.updateUser(userId, UserRole.CUSTOMER, userId, request);

        // then
        verify(mockUser, never()).changeEmail(any());
    }

    @Test
    @DisplayName("사용자 수정 성공 - userInfo가 null이면 프로필 업데이트를 건너뛴다")
    void updateUser_성공_userInfo_없으면_프로필_수정_생략() {
        // given
        UUID userId = UUID.randomUUID();
        User mockUser = mock(User.class);
        UserUpdateRequest request = new UserUpdateRequest(null, null, "new@email.com", null, null, null);

        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(mockUser);
        when(mockUser.getUserInfo()).thenReturn(null);
        when(mockUser.getUserId()).thenReturn(userId);
        when(mockUser.getUserRole()).thenReturn(UserRole.CUSTOMER);

        // when
        userService.updateUser(userId, UserRole.CUSTOMER, userId, request);

        // then
        verify(mockUser).changeEmail("new@email.com");
    }

    @Test
    @DisplayName("사용자 수정 실패 - CUSTOMER가 다른 사용자 수정 시도 시 ACCESS_DENIED가 발생한다")
    void updateUser_실패_CUSTOMER_타사용자_수정() {
        // given
        UUID authId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        UserUpdateRequest request = new UserUpdateRequest(null, null, "x@x.com", null, null, null);

        // when
        BizException ex = assertThrows(BizException.class,
            () -> userService.updateUser(authId, UserRole.CUSTOMER, targetId, request));

        // then
        assertEquals(CommonErrorCode.ACCESS_DENIED, ex.getResponseCode());
        verify(userRepository, never()).findByUserIdAndDeletedAtIsNull(any());
    }

    // ── getUsers ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("목록 조회 성공 - keyword가 있으면 searchType이 그대로 전달된다")
    void getUsers_성공_키워드_있음() {
        // given
        Pageable pageable = PageRequest.of(0, 10);
        User mockUser = buildMockUser(UUID.randomUUID(), UserRole.CUSTOMER);
        Page<User> page = new PageImpl<>(List.of(mockUser));

        when(userRepository.searchUsers(false, null, "username", "testuser", pageable))
            .thenReturn(page);

        // when
        List<UserGetResponse> result = userService.getUsers(false, null, "username", "testuser", pageable);

        // then
        assertThat(result).hasSize(1);
        verify(userRepository).searchUsers(false, null, "username", "testuser", pageable);
    }

    @Test
    @DisplayName("목록 조회 성공 - keyword가 없으면 searchType이 null로 치환되어 전달된다")
    void getUsers_성공_키워드_없으면_searchType_null() {
        // given
        Pageable pageable = PageRequest.of(0, 10);
        Page<User> page = new PageImpl<>(List.of());

        when(userRepository.searchUsers(eq(false), isNull(), isNull(), isNull(), eq(pageable)))
            .thenReturn(page);

        // when
        List<UserGetResponse> result = userService.getUsers(false, null, "username", null, pageable);

        // then
        assertThat(result).isEmpty();
        verify(userRepository).searchUsers(false, null, null, null, pageable);
    }

    @Test
    @DisplayName("목록 조회 성공 - 빈 keyword이면 searchType이 null로 치환되어 전달된다")
    void getUsers_성공_빈_키워드이면_searchType_null() {
        // given
        Pageable pageable = PageRequest.of(0, 10);
        Page<User> page = new PageImpl<>(List.of());

        when(userRepository.searchUsers(false, null, null, "  ", pageable))
            .thenReturn(page);

        // when
        userService.getUsers(false, null, "username", "  ", pageable);

        // then
        verify(userRepository).searchUsers(false, null, null, "  ", pageable);
    }

    // ── updatePassword ───────────────────────────────────────────────────────

    @Test
    @DisplayName("비밀번호 변경 성공 - 현재 비밀번호가 일치하면 새 비밀번호로 변경된다")
    void updatePassword_성공() {
        // given
        UUID userId = UUID.randomUUID();
        User mockUser = mock(User.class);
        UserPasswordUpdateRequest request = new UserPasswordUpdateRequest("Current1!", "NewPass1!");

        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(mockUser);
        when(mockUser.getPassword()).thenReturn("encoded-current");
        when(passwordEncoder.matches("Current1!", "encoded-current")).thenReturn(true);
        when(passwordEncoder.encode("NewPass1!")).thenReturn("encoded-new");

        // when
        userService.updatePassword(userId, UserRole.CUSTOMER, userId, request);

        // then
        verify(mockUser).changePassword("encoded-new");
    }

    @Test
    @DisplayName("비밀번호 변경 실패 - 현재 비밀번호가 일치하지 않으면 예외가 발생한다")
    void updatePassword_실패_현재_비밀번호_불일치() {
        // given
        UUID userId = UUID.randomUUID();
        User mockUser = mock(User.class);
        UserPasswordUpdateRequest request = new UserPasswordUpdateRequest("WrongCurrent!", "NewPass1!");

        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(mockUser);
        when(mockUser.getPassword()).thenReturn("encoded-current");
        when(passwordEncoder.matches("WrongCurrent!", "encoded-current")).thenReturn(false);

        // when
        BizException ex = assertThrows(BizException.class,
            () -> userService.updatePassword(userId, UserRole.CUSTOMER, userId, request));

        // then
        assertEquals(UserErrorCode.PASSWORD_NOT_MATCH, ex.getResponseCode());
        verify(mockUser, never()).changePassword(any());
    }

    @Test
    @DisplayName("비밀번호 변경 실패 - CUSTOMER가 다른 사용자 비밀번호 변경 시도 시 ACCESS_DENIED가 발생한다")
    void updatePassword_실패_CUSTOMER_타사용자_변경_시도() {
        // given
        UUID authId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        UserPasswordUpdateRequest request = new UserPasswordUpdateRequest("Current1!", "NewPass1!");

        // when
        BizException ex = assertThrows(BizException.class,
            () -> userService.updatePassword(authId, UserRole.CUSTOMER, targetId, request));

        // then
        assertEquals(CommonErrorCode.ACCESS_DENIED, ex.getResponseCode());
        verify(userRepository, never()).findByUserIdAndDeletedAtIsNull(any());
    }

    @Test
    @DisplayName("비밀번호 변경 성공 - MASTER는 다른 사용자의 비밀번호를 변경할 수 있다")
    void updatePassword_성공_MASTER_타사용자_변경() {
        // given
        UUID masterId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        User mockUser = mock(User.class);
        UserPasswordUpdateRequest request = new UserPasswordUpdateRequest("Current1!", "NewPass1!");

        when(userRepository.findByUserIdAndDeletedAtIsNull(targetId)).thenReturn(mockUser);
        when(mockUser.getPassword()).thenReturn("encoded-current");
        when(passwordEncoder.matches("Current1!", "encoded-current")).thenReturn(true);
        when(passwordEncoder.encode("NewPass1!")).thenReturn("encoded-new");

        // when
        userService.updatePassword(masterId, UserRole.MASTER, targetId, request);

        // then
        verify(mockUser).changePassword("encoded-new");
    }

    // ── deleteUser ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("회원 탈퇴 성공 - userInfo가 있으면 User와 UserInfo 모두 soft delete 된다")
    void deleteUser_성공_userInfo_있음() {
        // given
        UUID userId = UUID.randomUUID();
        User mockUser = mock(User.class);
        UserInfo mockUserInfo = mock(UserInfo.class);

        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(mockUser);
        when(mockUser.getUserInfo()).thenReturn(mockUserInfo);
        when(mockUser.getUserId()).thenReturn(userId);

        // when
        userService.deleteUser(userId, UserRole.CUSTOMER, userId);

        // then
        verify(mockUser).markDeleted(userId);
        verify(mockUserInfo).markDeleted(userId);
        verify(authCache).storeToken(eq(userId.toString()), anyLong());
    }

    @Test
    @DisplayName("회원 탈퇴 성공 - userInfo가 없으면 User만 soft delete 된다")
    void deleteUser_성공_userInfo_없음() {
        // given
        UUID userId = UUID.randomUUID();
        User mockUser = mock(User.class);

        when(userRepository.findByUserIdAndDeletedAtIsNull(userId)).thenReturn(mockUser);
        when(mockUser.getUserInfo()).thenReturn(null);
        when(mockUser.getUserId()).thenReturn(userId);

        // when
        userService.deleteUser(userId, UserRole.CUSTOMER, userId);

        // then
        verify(mockUser).markDeleted(userId);
        verify(authCache).storeToken(eq(userId.toString()), anyLong());
    }

    @Test
    @DisplayName("회원 탈퇴 성공 - MASTER는 다른 사용자를 탈퇴시킬 수 있다")
    void deleteUser_성공_MASTER_타사용자_탈퇴() {
        // given
        UUID masterId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();
        User mockUser = mock(User.class);

        when(userRepository.findByUserIdAndDeletedAtIsNull(targetId)).thenReturn(mockUser);
        when(mockUser.getUserInfo()).thenReturn(null);
        when(mockUser.getUserId()).thenReturn(targetId);

        // when
        userService.deleteUser(masterId, UserRole.MASTER, targetId);

        // then
        verify(mockUser).markDeleted(targetId);
        verify(authCache).storeToken(eq(targetId.toString()), anyLong());
    }

    @Test
    @DisplayName("회원 탈퇴 실패 - CUSTOMER가 다른 사용자 탈퇴 시도 시 ACCESS_DENIED가 발생한다")
    void deleteUser_실패_CUSTOMER_타사용자_탈퇴_시도() {
        // given
        UUID authId = UUID.randomUUID();
        UUID targetId = UUID.randomUUID();

        // when
        BizException ex = assertThrows(BizException.class,
            () -> userService.deleteUser(authId, UserRole.CUSTOMER, targetId));

        // then
        assertEquals(CommonErrorCode.ACCESS_DENIED, ex.getResponseCode());
        verify(userRepository, never()).findByUserIdAndDeletedAtIsNull(any());
        verify(authCache, never()).storeToken(anyString(), anyLong());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private User buildMockUser(UUID userId, UserRole role) {
        User mockUser = mock(User.class);
        when(mockUser.getUserId()).thenReturn(userId);
        when(mockUser.getUserRole()).thenReturn(role);
        when(mockUser.getUserInfo()).thenReturn(null);
        return mockUser;
    }
}
