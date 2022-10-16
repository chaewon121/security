//package com.example.security1.config.auth;
//
//@Service
//public class PrincipalDetailsService implements UserDetailsService{
//
//    @Autowired
//    private UserRepository userRepository;
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        User user = userRepository.findByUsername(username);
//        if(user == null) {
//            return null;
//        }
//        return new PrincipalDetails(user);
//    }
//
//}