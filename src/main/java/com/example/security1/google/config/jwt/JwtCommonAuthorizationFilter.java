package com.example.security1.google.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.security1.google.config.auth.PrincipalDetails;
import com.example.security1.google.model.UserEntity;
import com.example.security1.google.repository.UserRepository;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
//jwt 토큰이 유요한지 검증하는 필터
//권한이나 인증이 필요한 주소면 이 필터를 탐
public class JwtCommonAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;
    private JwtTokenProvider jwtTokenProvider;


    public JwtCommonAuthorizationFilter(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider, UserRepository userRepository) {
        super(authenticationManager);
        this.jwtTokenProvider = jwtTokenProvider;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("JwtCommonAuthorizationFilter의 dofilter탐");
        // Read the Authorization header, where the JWT token should be
        String header = request.getHeader("Authorization");


        // If header does not contain BEARER or is null delegate to Spring impl and exit
        if (header == null || !header.startsWith("Bearer")) {
            chain.doFilter(request, response);
            System.out.println("걸림");
            return;
        }
        // If header is present, try grab user principal from database and perform authorization
        Authentication authentication = getUsernamePasswordAuthentication(request);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // Continue filter execution
        chain.doFilter(request, response);
    }

    private Authentication getUsernamePasswordAuthentication(HttpServletRequest request) {
        System.out.println("JwtCommonAuthorizationFilter의 getUsernamePasswordAuthentication탐");
        String token = request.getHeader("Authorization")
                .replace("Bearer ","");
        System.out.println("token : " +token);
        if (token != null) {
            System.out.println("token != null");
//            Claims claims = jwtTokenProvider.getClaims(token);
//            String userUuid = claims.getSubject(); // getSubject 값은 users의 id값
//            System.out.println("claims의 userUuid : " + userUuid);

            String email = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token)
                    .getClaim("email").asString();
            System.out.println("username: " + email);

            if (email != null) {
                UserEntity user = userRepository.findByEmail(email);
                //UserEntity user = oUser.get();
                PrincipalDetails principalDetails = new PrincipalDetails(user);
                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(
                                principalDetails, //나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
                                null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
                                principalDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication); // 세션에 넣기
                return authentication;
            }
        }
        return null;
    }
}
