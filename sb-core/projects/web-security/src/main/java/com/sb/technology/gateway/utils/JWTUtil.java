package com.sb.technology.gateway.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Calendar;
import java.util.Date;
import java.util.stream.Collectors;

public class JWTUtil {

    private static final String SECURITY_KEY = "gongzx@1234";//静态字符密文
    private static final String ISSUER = "sb.core.gateway";
    public static final String AUTHENTICATION_COOKIE_NAME = "Authentication";

    private static Algorithm algorithm;

    public static Algorithm getAlgorithm(){
        if (algorithm == null){
            algorithm = Algorithm.HMAC256(SECURITY_KEY);
        }
        return algorithm;
    }

    /**
     *
     * @Author gongzexin@anewayer.com
     * @Description 创建令牌
     * @Date 2020-06-09 22:58
     */
    public static String encodeToken(Authentication authentication){
        String authorities = authentication.getAuthorities().stream().map(authority -> authority.getAuthority()).collect(Collectors.joining(", "));
        Calendar calendar = Calendar.getInstance();
        Date efficaciousTime = calendar.getTime();
        calendar.add(Calendar.HOUR_OF_DAY, 12);
        Date invalidTime = calendar.getTime();
        String token = JWT.create()
                .withIssuer(ISSUER)
                .withIssuedAt(efficaciousTime)
                .withNotBefore(efficaciousTime)
                .withExpiresAt(invalidTime)
                .withClaim("principal", ((UserDetails) authentication.getPrincipal()).getUsername())
                .withClaim("authorities", authorities)
                .sign(getAlgorithm());
        return token;
    }

    /**
     *
     * @Author gongzexin@anewayer.com
     * @Description 校验令牌
     * @Date 2020-06-09 23:05
     */
    public static DecodedJWT decodeToken(String token){
        JWTVerifier verifier = JWT.require(getAlgorithm())
                .withIssuer(ISSUER)
                .build();
        DecodedJWT decodedJWT = verifier.verify(token);
        return decodedJWT;
    }


}
