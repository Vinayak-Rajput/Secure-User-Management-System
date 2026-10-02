package com.hdfclife.capstoneone.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hdfclife.capstoneone.logging.AuditEventLogger;

import com.hdfclife.capstoneone.service.UserRegistrationService;
import com.hdfclife.capstoneone.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import com.hdfclife.capstoneone.dto.AdminCreateUserRequest;

import com.hdfclife.capstoneone.exception.UserNotFoundException;
import com.hdfclife.capstoneone.model.AuditEvent;
import com.hdfclife.capstoneone.model.AuditEventType;

import com.hdfclife.capstoneone.entity.User;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.ResultMatcher;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.web.servlet.function.RequestPredicates.contentType;

@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserService userService;

    @MockBean
    private UserRegistrationService userRegistrationService;

    @MockBean
    private AuditEventLogger auditEventLogger;

    private User sampleUser1;
    private User sampleUser2;

    @BeforeEach
    void setUp() {
        sampleUser1 = new User();
        sampleUser1.setUsername("admin_user");
        sampleUser1.setPassword("admin@1234");
        sampleUser1.setEmail("admin@example.com");
        sampleUser1.setRole("ADMIN");

        sampleUser2 = new User();
        sampleUser1.setUsername("john_doe");
        sampleUser1.setPassword("john@1234");
        sampleUser1.setEmail("john@example.com");
        sampleUser1.setRole("USER");
    }

    @Nested
    @DisplayName("GET /users - List All Users")
    class GetAllUsersTests {

        @Test
        @WithMockUser(username = "admin_user", roles = {"ADMIN"})
        @DisplayName("Should return 200 OK and user summary list when users exist")
        void getAllUsers_Success() throws Exception {
            given(userService.getAllUsers()).willReturn(List.of(sampleUser1, sampleUser2));

            mockMvc.perform(get("/users")
                            .accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect((ResultMatcher) contentType(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.length()").value(2))
                    .andExpect(jsonPath("$[0].id").value(1))
                    .andExpect(jsonPath("$[0].username").value("admin_user"))
                    .andExpect(jsonPath("$[1].id").value(2))
                    .andExpect(jsonPath("$[1].username").value("john_doe"));

            ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
            verify(auditEventLogger).log(eventCaptor.capture());

            AuditEvent captured = eventCaptor.getValue();
            assertThat(captured.type()).isEqualTo(AuditEventType.USER_LIST_VIEWED);
            assertThat(captured.actorUsername()).isEqualTo("admin_user");
            assertThat(captured.httpMethod()).isEqualTo("GET");
            assertThat(captured.requestPath()).isEqualTo("/users");
            assertThat(captured.httpStatus()).isEqualTo(200);
        }

        @Test
        @WithMockUser(username = "admin_user", roles = {"ADMIN"})
        @DisplayName("Should return 200 OK with empty array when no users exist")
        void getAllUsers_EmptyList() throws Exception {
            given(userService.getAllUsers()).willReturn(Collections.emptyList());

            mockMvc.perform(get("/users")
                            .accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.length()").value(0));

            verify(auditEventLogger).log(any(AuditEvent.class));
        }
    }

    @Nested
    @DisplayName("GET /users/me - View Self Account")
    class GetMyAccountTests {

        @Test
        @DisplayName("Should return 200 OK and current authenticated user summary")
        void getMyAccount_Success() throws Exception {
            UserDetails principal = new org.springframework.security.core.userdetails.User(
                    "john_doe",
                    "password",
                    List.of(new SimpleGrantedAuthority("ROLE_USER"))
            );

            given(userService.getUserByUsername("john_doe")).willReturn(sampleUser2);

            mockMvc.perform(get("/users/me")
                            .with(user(principal))
                            .accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect((ResultMatcher) contentType(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.id").value(2))
                    .andExpect(jsonPath("$.username").value("john_doe"))
                    .andExpect(jsonPath("$.email").value("john@example.com"));

            ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
            verify(auditEventLogger).log(eventCaptor.capture());

            AuditEvent captured = eventCaptor.getValue();
            assertThat(captured.type()).isEqualTo(AuditEventType.USER_SELF_VIEWED);
            assertThat(captured.actorUsername()).isEqualTo("john_doe");
            assertThat(captured.subjectUsername()).isEqualTo("john_doe");
            assertThat(captured.requestPath()).isEqualTo("/users/me");
            assertThat(captured.httpStatus()).isEqualTo(200);
        }
    }

    @Nested
    @DisplayName("GET /users/{id} - View User By ID")
    class GetUserByIdTests {

        @Test
        @WithMockUser(username = "admin_user", roles = {"ADMIN"})
        @DisplayName("Should return 200 OK and user details when user exists")
        void getUser_Success() throws Exception {
            given(userService.getUser(2L)).willReturn(sampleUser2);

            mockMvc.perform(get("/users/{id}", 2L)
                            .accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(2))
                    .andExpect(jsonPath("$.username").value("john_doe"))
                    .andExpect(jsonPath("$.email").value("john@example.com"));

            ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
            verify(auditEventLogger).log(eventCaptor.capture());

            AuditEvent captured = eventCaptor.getValue();
            assertThat(captured.type()).isEqualTo(AuditEventType.USER_VIEWED);
            assertThat(captured.actorUsername()).isEqualTo("admin_user");
            assertThat(captured.subjectUsername()).isEqualTo("john_doe");
            assertThat(captured.requestPath()).isEqualTo("/users/{id}");
            assertThat(captured.httpStatus()).isEqualTo(200);
        }

        @Test
        @WithMockUser(username = "admin_user", roles = {"ADMIN"})
        @DisplayName("Should return 404 NOT FOUND when target user ID does not exist")
        void getUser_NotFound() throws Exception {
            given(userService.getUser(99L)).willThrow(new UserNotFoundException("User not found with id: 99"));

            mockMvc.perform(get("/users/{id}", 99L)
                            .accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isNotFound());
        }
    }

    @Nested
    @DisplayName("POST /users - Create Admin-Managed User")
    class AddUserTests {

        @Test
        @WithMockUser(username = "admin_user", roles = {"ADMIN"})
        @DisplayName("Should return 201 CREATED when request is valid")
        void addUser_Success() throws Exception {
            AdminCreateUserRequest request = new AdminCreateUserRequest(
                    "new_user",
                    "newuser@example.com",
                    "SecurePassword123!",
                    "USER"
            );

            User createdUser = new User();

            createdUser.setUsername("new_user");
            createdUser.setPassword("SecurePassword123!");
            createdUser.setEmail("newuser@example.com");
            createdUser.setRole("USER");


            given(userRegistrationService.createAdminManagedUser(
                    eq("new_user"),
                    eq("newuser@example.com"),
                    eq("SecurePassword123!"),
                    eq("RUSER")
            )).willReturn(createdUser);

            mockMvc.perform(post("/users")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request))
                            .accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id").value(3))
                    .andExpect(jsonPath("$.username").value("new_user"))
                    .andExpect(jsonPath("$.email").value("newuser@example.com"));

            ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
            verify(auditEventLogger).log(eventCaptor.capture());

            AuditEvent captured = eventCaptor.getValue();
            assertThat(captured.type()).isEqualTo(AuditEventType.USER_CREATED);
            assertThat(captured.actorUsername()).isEqualTo("admin_user");
            assertThat(captured.subjectUsername()).isEqualTo("new_user");
            assertThat(captured.httpMethod()).isEqualTo("POST");
            assertThat(captured.httpStatus()).isEqualTo(201);
        }

        @Test
        @WithMockUser(username = "admin_user", roles = {"ADMIN"})
        @DisplayName("Should return 400 BAD REQUEST when body validation fails")
        void addUser_ValidationError() throws Exception {
            AdminCreateUserRequest invalidRequest = new AdminCreateUserRequest(
                    "",
                    "invalid-email",
                    "short",
                    null
            );

            mockMvc.perform(post("/users")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(invalidRequest)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("DELETE /users/{id} - Delete User Account")
    class DeleteUserTests {

        @Test
        @WithMockUser(username = "admin_user", roles = {"ADMIN"})
        @DisplayName("Should return 204 NO CONTENT on successful deletion")
        void deleteUser_Success() throws Exception {
            given(userService.deleteUser(2L, "admin_user")).willReturn("john_doe");

            mockMvc.perform(delete("/users/{id}", 2L))
                    .andExpect(status().isNoContent());

            verify(userService).deleteUser(2L, "admin_user");

            ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
            verify(auditEventLogger).log(eventCaptor.capture());

            AuditEvent captured = eventCaptor.getValue();
            assertThat(captured.type()).isEqualTo(AuditEventType.USER_DELETED);
            assertThat(captured.actorUsername()).isEqualTo("admin_user");
            assertThat(captured.subjectUsername()).isEqualTo("john_doe");
            assertThat(captured.httpMethod()).isEqualTo("DELETE");
            assertThat(captured.requestPath()).isEqualTo("/users/{id}");
            assertThat(captured.httpStatus()).isEqualTo(204);
        }

        @Test
        @WithMockUser(username = "admin_user", roles = {"ADMIN"})
        @DisplayName("Should return 404 NOT FOUND when deleting a non-existent user")
        void deleteUser_NotFound() throws Exception {
            given(userService.deleteUser(99L, "admin_user"))
                    .willThrow(new UserNotFoundException("User not found"));

            mockMvc.perform(delete("/users/{id}", 99L))
                    .andExpect(status().isNotFound());
        }
    }
}