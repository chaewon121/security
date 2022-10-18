package com.example.security1.google.controller;

import com.example.security1.google.model.UserEntity;
import com.example.security1.google.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller //vuew를 리턴

public class IndexController {

    @Autowired
    private UserRepository userRepository;

//    @Autowired
//    private BCryptPasswordEncoder bCryptPasswordEncoder;

//    @GetMapping("/member/kakao/callback")
//    public @ResponseBody String kakao(String code) {
//
//        System.out.println("code: "+code);
//        return "kakao 페이지입니다.";
//    }


    @GetMapping({ "", "/" })
    public @ResponseBody String index() {

        return "인덱스 페이지입니다.";
    }

    @GetMapping("/user")
    public @ResponseBody String user(
           // @AuthenticationPrincipal PrincipalDetails principal
    ) {
//        System.out.println("Principal : " + principal);
//        // iterator 순차 출력 해보기
//        Iterator<? extends GrantedAuthority> iter = principal.getAuthorities().iterator();
//        while (iter.hasNext()) {
//            GrantedAuthority auth = iter.next();
//            System.out.println(auth.getAuthority());
//        }

        return "유저 페이지입니다.";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "어드민 페이지입니다.";
    }

    //@PostAuthorize("hasRole('ROLE_MANAGER')")
    //@PreAuthorize("hasRole('ROLE_MANAGER')")
    @Secured("ROLE_MANAGER")
    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "매니저 페이지입니다.";
    }

    //시큐리티가 이 주소를 낚아채버리네요!
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/join")
    public String join() {
        return "join";
    }

    @PostMapping("/joinProc")
    public String joinProc(UserEntity user) {
        System.out.println("회원가입 진행 : " + user);
        String rawPassword = user.getPassword();
       // String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(rawPassword);
        user.setRole("ROLE_USER");
        userRepository.save(user);
        return "redirect:/";
    }
    @Secured("ROLE_MANAGER")
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }
    //PreAuthorize는 여러개 결고 싶을때
    @PreAuthorize("hasRole('ROLE_MANAGER')or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data() {

        return "데이터정보";
    }
}
