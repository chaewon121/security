package com.example.security1.google.config;
import com.example.security1.google.config.oauth.PrincipalOauth2UserService;
import com.example.security1.google.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.filters.AddDefaultCharsetFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

//1.코드받기,2.엑세스토큰받기(권한이생김),
//3 사용자프로필정보가져와 4-1.그정보를 토대로 회원가입자동으로 진행
//4-2


@Configuration // IoC 빈(bean)을 등록
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록됨
//secured 어노테이션 활성화
//preAuthorize 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true) // 특정 주소 접근시 권한 및 인증을 위한 어노테이션 활성화
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }
    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;
    //private final OAuth2SuccessHandler successHandler;
    //private final JwtService jwtService;
    private final CorsConfig corsConfig;

    private final UserRepository userRepository;
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .addFilter(corsConfig.corsFilter());
//                .addFilter(new JwtAuthenticationFilter(authenticationManager(), jwtService)) //AuthenticationManger가 있어야 된다.(파라미터로)
//                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository, jwtService));


        http.httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                //.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_USER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN') and hasRole('ROLE_USER')")
                //.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                //권한이 없는 페이지로 이동할때 로그인 페이지로 이동
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/loginProc")
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/login")
                //.successHandler(successHandler)
                .userInfoEndpoint()
                .userService(principalOauth2UserService);

        ; //구글로그인이 완료된 뒤의 후처리가 필요함
        //http.addFilterBefore(new JwtAuthFilter(tokenService), UsernamePasswordAuthenticationFilter.class);

    }
}

