package br.com.jatai.security.util;

import br.com.jatai.security.dto.AuthenticationRequestDTO;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${api.security.token.secret}")
    private String secretKey;

    @Value("${api.security.token.jwt.expiration}")
    private long expiration;

    public String generateToken(AuthenticationRequestDTO dto) {
        Date now = new Date();

        return Jwts.builder()
                .issuer("API Jataí")
                .subject(dto.getUserEmail())
                .claim("uuid", dto.getUserUuid())
                .issuedAt(now)
                .expiration(new Date(now.getTime() + expiration))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                .compact();
    }

    public String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            JwtParser jwtParser = getJwtParser();
            jwtParser.parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        JwtParser jwtParser = getJwtParser();
        Claims claims = jwtParser.parseSignedClaims(token).getPayload();
        return claims.getSubject();
    }

    public Date getExpirationDateFromToken(String token){
        JwtParser jwtParser = getJwtParser();
        Claims claims = jwtParser.parseSignedClaims(token).getPayload();
        return claims.getExpiration();
    }

    public boolean isTokenExpired(String token) {
        Date expirationDate = getExpirationDateFromToken(token);
        return expirationDate.before(new Date());
    }

    private JwtParser getJwtParser() {
        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes());
        return Jwts.parser().verifyWith(key).build();
    }
}
