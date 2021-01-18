package me.hajoo.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import lombok.extern.slf4j.Slf4j;
import me.hajoo.jwt.Repository.UserRepository;
import me.hajoo.jwt.config.auth.PrincipalDetails;
import me.hajoo.jwt.domain.User;
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

// BasicAuthenticationFilter
// 권한이나 인증이 필요한 특정 주소를 요청할 때 위에 필터를 거친다
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 페이지로 요청이 옴");

        String jwtHeader = request.getHeader("Authorization");

        // header가 있는지
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

        try {
            String username = JWT.require(Algorithm.HMAC512("cos")).build()
                    .verify(jwtToken).getClaim("username").asString();

            // 서명이 정상적으로 이루어짐
            if(username != null){

                User user = userRepository.findByUsername(username);

                PrincipalDetails principalDetails = new PrincipalDetails(user);
                // Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만듬
                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

                // 강제로 시큐리티의 세션에 접근하여 Authentication 객체에 저장
                SecurityContextHolder.getContext().setAuthentication(authentication);

                chain.doFilter(request, response);
            }
        } catch (TokenExpiredException ignored){
            log.info("토큰 기간이 만료되었습니다.");
        } catch (SignatureVerificationException e){
            log.info("토큰이 누군가에 의해 변경되었습니다.");
        } catch (NullPointerException e){
            log.info("해당 토큰에 사용자가 존재하지 않습니다.");
        }

    }
}
