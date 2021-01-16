package me.hajoo.jwt.controller;

import lombok.RequiredArgsConstructor;
import me.hajoo.jwt.Repository.UserRepository;
import me.hajoo.jwt.config.auth.PrincipalDetails;
import me.hajoo.jwt.domain.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class UserController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(){
        User user = new User();
        user.changeUsername("hajoo");
        user.changePassword(passwordEncoder.encode("1234"));
        user.changeRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    @PostMapping("/user")
    public String user(){
        return "user";
    }

    @GetMapping("/manager")
    public String manager(){
        return "manager";
    }
}
