package br.com.jatai.security.service;

import br.com.jatai.security.dto.AuthenticationRequestDTO;
import br.com.jatai.security.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class AuthenticationService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    public String authenticate(AuthenticationRequestDTO dto) {
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(dto.getUserEmail(), dto.getUserPassword(), Collections.singletonList(new SimpleGrantedAuthority(dto.getUserRole())));
        authRequest.setDetails(dto.getUserPassworEncripted());
        Authentication authentication = authenticationManager.authenticate(authRequest);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return jwtUtil.generateToken(dto);
    }

    public String passwordEncoder(String passUncrypted){
        return passwordEncoder.encode(passUncrypted);
    }
}
