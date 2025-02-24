package br.com.jatai.security.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import java.util.UUID;

public class AuthenticationRequestDTO {
    @NotBlank @Email
    String userEmail;

    @NotBlank
    String userPassword;

    @NotBlank
    String userPassworEncripted;

    @NotBlank
    UUID userUuid;

    @NotBlank
    String userRole;

    public AuthenticationRequestDTO(String userEmail, String userPassword, String userPassworEncripted, UUID userUuid, String userRole) {
        this.userEmail = userEmail;
        this.userPassword = userPassword;
        this.userPassworEncripted = userPassworEncripted;
        this.userUuid = userUuid;
        this.userRole = userRole;
    }

    public void setUserPassword(String userPassword) {
        this.userPassword = userPassword;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public String getUserPassword() {
        return userPassword;
    }

    public String getUserPassworEncripted() {
        return userPassworEncripted;
    }

    public UUID getUserUuid() {
        return userUuid;
    }

    public String getUserRole() {
        return userRole;
    }
}
