package me.hajoo.jwt.config.auth;

import lombok.RequiredArgsConstructor;
import me.hajoo.jwt.Repository.UserRepository;
import me.hajoo.jwt.domain.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipleDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null){
            throw new UsernameNotFoundException("not found username" + username);
        }else{
            return new PrincipalDetails(user);
        }
    }
}
