//package com.example.security1.config.auth;
//
//// Authentication 객체에 저장할 수 있는 유일한 타입
//@Data
//public class PrincipalDetails implements UserDetails{
//
//    private User user;
//
//    public PrincipalDetails(User user) {
//        super();
//        this.user = user;
//    }
//
//    @Override
//    public String getPassword() {
//        return user.getPassword();
//    }
//
//    @Override
//    public String getUsername() {
//        return user.getUsername();
//    }
//
//    @Override
//    public boolean isAccountNonExpired() {
//        return true;
//    }
//
//    @Override
//    public boolean isAccountNonLocked() {
//        return true;
//    }
//
//    @Override
//    public boolean isCredentialsNonExpired() {
//        return true;
//    }
//
//    @Override
//    public boolean isEnabled() {
//        return true;
//    }
//
//    @Override
//    public Collection<? extends GrantedAuthority> getAuthorities() {
//        Collection<GrantedAuthority> collet = new ArrayList<GrantedAuthority>();
//        collet.add(()->{ return user.getRole();});
//        return collet;
//    }
//
//
//
//}
//Footer
//        © 2022 GitHub, Inc.
//        Footer navigation
//        Terms
//        Privacy
//        Sec
