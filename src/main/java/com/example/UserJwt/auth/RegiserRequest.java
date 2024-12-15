package com.example.UserJwt.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegiserRequest {
    private String firstname;
    private String lastname;
    private String email;
    private String password;

}
