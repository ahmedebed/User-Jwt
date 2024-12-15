package com.example.UserJwt.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    @Autowired
    public AuthenticationController(AuthenticationService authenticationService){
        this.authenticationService=authenticationService;
    }
    @PostMapping("/register")
    public ResponseEntity<Object> register(
            @RequestBody RegiserRequest request){
        return ResponseEntity.ok(authenticationService.register(request));


    }
    @PostMapping("/authenticate")
    public ResponseEntity<Object> register(
            @RequestBody AuthenticationRequest request
    ){
        return ResponseEntity.ok(authenticationService.authenticate(request));

    }

}
