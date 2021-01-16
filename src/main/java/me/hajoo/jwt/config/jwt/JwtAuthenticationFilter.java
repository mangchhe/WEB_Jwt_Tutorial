package me.hajoo.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import me.hajoo.jwt.config.auth.PrincipalDetails;
import me.hajoo.jwt.domain.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// Spring Security 에서 UsernamePasswordAuthenticationFilter 존재
// /login POST 요청해서 username, password 전송하면 UsernamePasswordAuthenticationFilter 동작
// formLogin 을 disable 해놔서 자동으로 작동하지 않는다.

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        System.out.println("로그인 시도");

        try {

            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.readValue(request.getInputStream(), User.class);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                            user.getUsername(),
                            user.getPassword()
                    );

            // PrincipalDetailsService의 loadUserByUserName() 함수 실행
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            // 로그인 완료
            PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();

            // authentication 객체가 session 영역에 저장 [security가 세션 관리를 대신 해주기 때문에 리턴]
            // JWT 토큰을 사용하면서 세션을 만들 이유가 없지만, 권한 처리 때문에 session을 넣어줌
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 처리 되었으면 실행
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("로그인 후 토큰 생성");

        PrincipalDetails principal = (PrincipalDetails) authResult.getPrincipal();

        String key = "cos";

        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + 60000))
                .withClaim("id", principal.getUser().getId())
                .withClaim("username", principal.getUser().getUsername())
                .sign(Algorithm.HMAC512(key));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
