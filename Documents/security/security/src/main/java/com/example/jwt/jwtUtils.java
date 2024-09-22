package com.example.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Component
public class jwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(jwtUtils.class);

//    need to configure in application.properties file
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private String jwtExpirationMs;

    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}",bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7); // Remove bearer from starting
        }
        return null;
    }

    public String generateJwtFroUsername(UserDetails userDetails){
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() +jwtExpirationMs))
                .signWith(key())
                .compact();


    }
    public String getUsernameFromJWt(String Token){
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(Token)
                .getPayload()
                .getSubject();
    }

    public Key key()
    {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validationJwt(String authToken){

        try{
            System.out.println("validation");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;
        }
        catch (MalformedJwtException e){
           logger.error("Invalid jwt Token: {}",e.getMessage());
        }
        catch (ExpiredJwtException e){
            logger.error("JWT token is expired: {}",e.getMessage());
        }
        catch (UnsupportedJwtException e){
            logger.error("JWT Token is Unsupported: {}",e.getMessage());
        }
        catch (IllegalArgumentException e){
            logger.error("JWT Claims Token is empty: {}",e.getMessage());
        }
        return false;
    }


}
