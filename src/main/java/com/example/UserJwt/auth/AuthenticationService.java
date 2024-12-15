package com.example.UserJwt.auth;

import com.example.UserJwt.config.JwtService;
import com.example.UserJwt.user.Role;
import com.example.UserJwt.user.User;
import com.example.UserJwt.user.UserRepository;
import lombok.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Builder
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    @Autowired
    public AuthenticationService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            AuthenticationManager authenticationManager){
        this.userRepository=userRepository;
        this.passwordEncoder=passwordEncoder;
        this.jwtService=jwtService;
        this.authenticationManager=authenticationManager;
    }


    public Object register(RegiserRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .pass(passwordEncoder.encode(request.getPassword() ))
                .role(Role.USER)



                .build();
        userRepository.save(user);
        var jwtToken=jwtService.generateToken(user);


        return AuthenticatinResponse.builder()
                .token(jwtToken)
                .build();
    }

    public Object authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken =jwtService.generateToken(user);

        return AuthenticatinResponse.builder()
                .token(jwtToken)
                .build()
                ;
    }
}
