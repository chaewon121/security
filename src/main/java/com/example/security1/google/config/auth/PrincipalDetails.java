package com.example.security1.google.config.auth;

import com.example.security1.google.model.UserEntity;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

// Authentication 객체에 저장할 수 있는 유일한 타입
//로그인 진행이 완료되면 시큐리티 session에 만들어줌(Security ContexHolder)
//여기에 들어갈수 있는 오브젝트는 Authentication 객체여야한다
//그리고 여기 안에는 user정보가 있어야함
//이 user오브젝트 타입은 UserDetails타입객체

//시큐리티session<- authentication <-UserDetails
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private UserEntity user;
    private Map<String, Object> attributes;

    //일반로그인
    public PrincipalDetails(UserEntity user) {
        this.user = user;
    }

    //OAUth로그인
    public PrincipalDetails(UserEntity user,Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public String getPassword() {

        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        //1년동안 회원이 로그인을 안하면 휴면계정으로 하기로함
        //user.getLoginDate()를 들고와서 1년 초과하면 return false;
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
    }

    //user의 권한을 리턴하는곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collet = new ArrayList<GrantedAuthority>();
        collet.add(()->{
            return user.getRole();});
        return collet;
    }


}
